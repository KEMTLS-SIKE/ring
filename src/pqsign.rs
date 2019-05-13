//! Wraps the post-quantum signature schemes in something slightly more usable
//! for Ring.
//!
//! Todo:
//! * Figure out desired API (probably steal from ECDSA/RSA)
//!     * Only RSA has PKCS1
//! * Import signature schemes from pqcrypto

use pqcrypto::{
    sign::sphincsshake256128fsimple,
    traits::sign::{DetachedSignature, PublicKey, SecretKey},
};

use crate::{error, io::der, pkcs8, sealed, signature};
use untrusted;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AlgorithmID {
    SPHINCS_SHAKE_256_128F_SIMPLE = 0xFE01,
}

// old stuff below

#[derive(Clone)]
pub struct PQPublicKey {
    alg: &'static PQSignatureScheme,
    key: Vec<u8>,
}

impl AsRef<[u8]> for PQPublicKey {
    fn as_ref(&self) -> &[u8] { self.key.as_ref() }
}

pub struct PQSecretKey {
    alg: &'static PQSignatureScheme,
    key: Vec<u8>,
}

pub struct PQSignature {
    id: AlgorithmID,
    signature: Vec<u8>,
}

pub struct PQKeyPair {
    pub pk: PQPublicKey,
    pub sk: PQSecretKey,
}

impl PQSecretKey {
    // from pkcs8
    pub fn from_pkcs8(
        alg: &'static PQSignatureScheme, input: untrusted::Input,
    ) -> Result<Self, error::KeyRejected> {
        let mut template = b"\x06\x0B\x2B\x06\x01\x04\x01\x82\x37\x59\x02".to_vec();
        template.push((alg.id as u16 >> 2) as u8);
        template.push(alg.id as u8);
        let (input, _) = pkcs8::unwrap_key_(&template, pkcs8::Version::V1OrV2, input)?;

        let private_key = input.read_all(error::KeyRejected::invalid_encoding(), |input| {
            der::nested(
                input,
                der::Tag::OctetString,
                error::KeyRejected::invalid_encoding(),
                |input| {
                    let key = der::expect_tag_and_get_value(input, der::Tag::OctetString)
                        .map_err(|_| error::KeyRejected::invalid_encoding())?;
                    Ok(key)
                },
            )
        })?;

        Ok(PQSecretKey {
            alg,
            key: private_key.as_slice_less_safe().to_vec(),
        })
    }

    pub fn sign(&self, msg: untrusted::Input) -> Result<signature::Signature, error::Unspecified> {
        Ok(signature::Signature::new(|sig_bytes| {
            debug_assert_eq!(sig_bytes.len(), 0);
            let sig = (self.alg.sign)(msg.as_slice_less_safe(), self);
            sig_bytes.extend_from_slice(&sig.signature);
            sig.signature.len()
        }))
    }
}

impl std::fmt::Debug for PQPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Keypair {:?}", self.alg.id)
    }
}

impl std::fmt::Debug for PQSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Keypair {:?}", self.alg.id)
    }
}

impl signature::KeyPair for PQPublicKey {
    type PublicKey = PQPublicKey;

    fn public_key(&self) -> &PQPublicKey { &self }
}

pub struct PQSignatureScheme {
    pub keypair: fn() -> PQKeyPair,

    pub sign: fn(&[u8], &PQSecretKey) -> PQSignature,

    pub id: AlgorithmID,

    pub verify: for<'a, 'b, 'c> fn(&'a [u8], &'b PQSignature, &'c PQPublicKey) -> bool,

    pub pk_from_slice: fn(&[u8]) -> PQPublicKey,
    pub sk_from_slice: fn(&[u8]) -> PQSecretKey,
}

impl sealed::Sealed for PQSignatureScheme {}

derive_debug_via_id!(PQSignatureScheme);

impl signature::VerificationAlgorithm for PQSignatureScheme {
    fn verify(
        &self, public_key: untrusted::Input, msg: untrusted::Input, signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let pk = (self.pk_from_slice)(public_key.as_slice_less_safe());
        let sig = PQSignature {
            id: self.id,
            signature: signature.as_slice_less_safe().to_vec(),
        };
        if (self.verify)(msg.as_slice_less_safe(), &sig, &pk) {
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }
}

#[allow(unused)]
pub static SPHINCS_SHAKE_256_128F_SIMPLE: PQSignatureScheme = PQSignatureScheme {
    id: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
    keypair: || {
        let (pk, sk) = sphincsshake256128fsimple::keypair();
        let pqpk = PQPublicKey {
            alg: &SPHINCS_SHAKE_256_128F_SIMPLE,
            key: pk.as_bytes().to_vec(),
        };
        let pqsk = PQSecretKey {
            alg: &SPHINCS_SHAKE_256_128F_SIMPLE,
            key: sk.as_bytes().to_vec(),
        };
        PQKeyPair { pk: pqpk, sk: pqsk }
    },
    pk_from_slice: |pk: &[u8]| PQPublicKey {
        alg: &SPHINCS_SHAKE_256_128F_SIMPLE,
        key: pk.to_vec(),
    },
    sk_from_slice: |sk: &[u8]| PQSecretKey {
        alg: &SPHINCS_SHAKE_256_128F_SIMPLE,
        key: sk.to_vec(),
    },
    sign: |message: &[u8], sk: &PQSecretKey| {
        debug_assert_eq!(sk.alg.id, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        let sk = sphincsshake256128fsimple::SecretKey::from_bytes(&sk.key);
        let sig = sphincsshake256128fsimple::detached_sign(message, &sk);
        PQSignature {
            id: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
            signature: sig.as_bytes().to_vec(),
        }
    },
    verify: |message: &[u8], sig: &PQSignature, pk: &PQPublicKey| {
        debug_assert_eq!(pk.alg.id, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        debug_assert_eq!(sig.id, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        let sig = sphincsshake256128fsimple::DetachedSignature::from_bytes(&sig.signature);
        let pk = sphincsshake256128fsimple::PublicKey::from_bytes(&pk.key);
        sphincsshake256128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
    },
};

#[cfg(test)]
mod tests {

    use super::*;
    use crate::signature;
    use untrusted::Input;

    #[test]
    fn test_signatures_scheme_sphincs_shake_256_128f_simple() {
        let scheme = &SPHINCS_SHAKE_256_128F_SIMPLE;

        let mut message = [0u8; 64];
        let keypair = (scheme.keypair)();
        let sig = (scheme.sign)(&message, &keypair.sk);
        assert!((scheme.verify)(&message, &sig, &keypair.pk));
        message[10] = 1;
        assert!(!(scheme.verify)(&message, &sig, &keypair.pk));
    }

    #[test]
    fn test_pqsecretkey() {
        let scheme = &SPHINCS_SHAKE_256_128F_SIMPLE;

        let message = Input::from(&[0u8; 64]);
        let message2 = Input::from(&[1u8; 64]);
        let keypair = (scheme.keypair)();
        let sig = keypair.sk.sign(message);
        assert!(sig.is_ok());
        assert!(signature::verify(
            scheme,
            Input::from(&keypair.pk.key),
            message,
            Input::from(&sig.clone().unwrap().as_ref())
        )
        .is_ok());
        assert!(!signature::verify(
            scheme,
            Input::from(&keypair.pk.key),
            message2,
            Input::from(&sig.unwrap().as_ref())
        )
        .is_ok());
    }
}
