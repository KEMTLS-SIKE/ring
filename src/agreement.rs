// Copyright 2015-2017 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Key Agreement: ECDH, including X25519.
//!
//! # Example
//!
//! Note that this example uses X25519, but ECDH using NIST P-256/P-384 is done
//! exactly the same way, just substituting
//! `agreement::ECDH_P256`/`agreement::ECDH_P384` for `agreement::X25519`.
//!
//! ```
//! # fn x25519_agreement_example() -> Result<(), ring::error::Unspecified> {
//! use ring::{agreement, rand};
//! use untrusted;
//!
//! let rng = rand::SystemRandom::new();
//!
//! let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!
//! // Make `my_public_key` a byte slice containing my public key. In a real
//! // application, this would be sent to the peer in an encoded protocol
//! // message.
//! let my_public_key = my_private_key.compute_public_key()?;
//!
//! // In a real application, the peer public key would be parsed out of a
//! // protocol message. Here we just generate one.
//! let peer_public_key = {
//!     let peer_private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)?;
//!     peer_private_key.compute_public_key()?
//! };
//! let peer_public_key = untrusted::Input::from(peer_public_key.as_ref());
//!
//! // In a real application, the protocol specifies how to determine what
//! // algorithm was used to generate the peer's private key. Here, we know it
//! // is X25519 since we just generated it.
//! let peer_public_key_alg = &agreement::X25519;
//!
//! agreement::agree_ephemeral(
//!     my_private_key,
//!     peer_public_key_alg,
//!     peer_public_key,
//!     ring::error::Unspecified,
//!     |_key_material| {
//!         // In a real application, we'd apply a KDF to the key material and the
//!         // public keys (as recommended in RFC 7748) and then derive session
//!         // keys from the result. We omit all that here.
//!         Ok(())
//!     },
//! )
//! # }
//! # fn main() { x25519_agreement_example().unwrap() }
//! ```

// The "NSA Guide" steps here are from from section 3.1, "Ephemeral Unified
// Model."

use crate::{ec, error, rand};
use untrusted;

pub use crate::ec::{
    csidh::CSIDH,
    curve25519::x25519::X25519,
    suite_b::ecdh::{ECDH_P256, ECDH_P384},
};

pub use crate::kem::{
    self,
    KYBER512,
    KYBER768,
    KYBER1024,
};

#[derive(Debug, PartialEq)]
pub(crate) enum AlgorithmIdentifier {
    Curve(&'static ec::Curve),
    KEM,
}

pub(crate) enum PrivateKey {
    ECPrivateKey(Box<ec::Seed>),
    KemPrivateKey(Vec<u8>),
}

/// A key agreement algorithm.
pub struct Algorithm {
    pub(crate) algorithm: AlgorithmIdentifier,
    pub(crate) decapsulate: fn(
        private_key: &PrivateKey,
        ciphertext: untrusted::Input,
    ) -> Result<Vec<u8>, error::Unspecified>,
    pub(crate) encapsulate: fn(
        peer_public_key: untrusted::Input,
        rng: &rand::SecureRandom,
    ) -> Result<(Ciphertext, SharedSecret), error::Unspecified>,
    pub(crate) keypair:
        fn(rng: &rand::SecureRandom) -> Result<(PrivateKey, PublicKey), error::Unspecified>,
}

pub type SharedSecret = Vec<u8>;

derive_debug_via_field!(Algorithm, algorithm);

impl Eq for Algorithm {}
impl PartialEq for Algorithm {
    fn eq(&self, other: &Algorithm) -> bool { self.algorithm == other.algorithm }
}

/// An ephemeral private key for use (only) with `agree_ephemeral`. The
/// signature of `agree_ephemeral` ensures that an `EphemeralPrivateKey` can be
/// used for at most one key agreement.
pub struct EphemeralPrivateKey {
    private_key: PrivateKey,
    alg: &'static Algorithm,
    public_key: Option<PublicKey>,
}

impl<'a> EphemeralPrivateKey {
    /// Generate a new ephemeral private key for the given algorithm.
    pub fn generate(
        alg: &'static Algorithm,
        rng: &rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        let (private_key, public_key) = (alg.keypair)(rng)?;
        Ok(Self {
            private_key,
            alg,
            public_key: Some(public_key),
        })
    }

    /// Computes the public key from the private key.
    #[inline(always)]
    pub fn compute_public_key(&self) -> Result<PublicKey, error::Unspecified> {
        if let Some(ref public_key) = self.public_key {
            Ok(public_key.clone())
        } else if let PrivateKey::ECPrivateKey(private_key) = &self.private_key {
            // NSA Guide Step 1.
            //
            // Obviously, this only handles the part of Step 1 between the private
            // key generation and the sending of the public key to the peer. `out`
            // is what should be sent to the peer.
            private_key.compute_public_key().map(|k| PublicKey::ECPublicKey(Box::new(k)))
        } else {
            Err(error::Unspecified)
        }
    }

    /// Encapsulate to public key
    pub fn encapsulate<F, R, E>(
        &self,
        peer_public_key: untrusted::Input,
        error_value: E,
        kdf: F,
    ) -> Result<(Ciphertext, R), E>
    where
        F: FnOnce(&[u8]) -> Result<R, E>,
    {
        let rng = rand::SystemRandom::new();
        let (ct, shared_key) = (self.alg.encapsulate)(peer_public_key, &rng)
                                    .map_err(|_| error_value)?;

        Ok((ct, kdf(&shared_key)?))
    }

    pub fn decapsulate<F, R, E>(
        &self,
        peer_public_value: untrusted::Input,
        error_value: E,
        kdf: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&[u8]) -> Result<R, E>,
    {
        let ss = (self.alg.decapsulate)(&self.private_key, peer_public_value).map_err(|_| error_value)?;
        Ok(kdf(&ss)?)
    }

    #[cfg(test)]
    pub fn bytes(&'a self) -> &'a [u8] { self.private_key.bytes_less_safe() }
}

#[derive(Clone)]
pub enum PublicKey {
    ECPublicKey(Box<ec::PublicKey>),
    KemPublicKey(Vec<u8>),
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::ECPublicKey(x) => x.as_ref().as_ref(),
            PublicKey::KemPublicKey(x) => x.as_ref(),
        }
    }
}

derive_debug_self_as_ref_hex_bytes!(PublicKey);

/// The public value for key agreement
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn new(vec: Vec<u8>) -> Self { Ciphertext(vec) }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

derive_debug_self_as_ref_hex_bytes!(Ciphertext);

/// Performs a key agreement with an ephemeral private key and the given public
/// key.
///
/// `my_private_key` is the ephemeral private key to use. Since it is moved, it
/// will not be usable after calling `agree_ephemeral`, thus guaranteeing that
/// the key is used for only one key agreement.
///
/// `peer_public_key_alg` is the algorithm/curve for the peer's public key
/// point; `agree_ephemeral` will return `Err(error_value)` if it does not
/// match `my_private_key's` algorithm/curve.
///
/// `peer_public_key` is the peer's public key. `agree_ephemeral` verifies that
/// it is encoded in the standard form for the algorithm and that the key is
/// *valid*; see the algorithm's documentation for details on how keys are to
/// be encoded and what constitutes a valid key for that algorithm.
///
/// `error_value` is the value to return if an error occurs before `kdf` is
/// called, e.g. when decoding of the peer's public key fails or when the public
/// key is otherwise invalid.
///
/// After the key agreement is done, `agree_ephemeral` calls `kdf` with the raw
/// key material from the key agreement operation and then returns what `kdf`
/// returns.
pub fn decapsulate<F, R, E>(
    my_private_key: EphemeralPrivateKey,
    peer_public_value: untrusted::Input,
    error_value: E,
    kdf: F,
) -> Result<R, E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    my_private_key.decapsulate(peer_public_value, error_value, kdf)
}

pub fn encapsulate<F, R, E>(
    rng: &dyn rand::SecureRandom,
    algorithm: &Algorithm,
    peer_public_key: untrusted::Input,
    error_value: E,
    kdf: F,
) -> Result<(Ciphertext, R), E>
where
    F: FnOnce(&[u8]) -> Result<R, E>,
{
    let (ct, ss) = (algorithm.encapsulate)(peer_public_key, rng).map_err(|_| error_value)?;
    let ss = kdf(&ss)?;
    Ok((ct, ss))
}
