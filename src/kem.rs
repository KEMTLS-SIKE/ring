

use crate::{agreement, error, rand};
use untrusted;

pub use pqcrypto::traits::kem::PublicKey;

#[derive(Debug, PartialEq)]
pub(crate) enum Algorithm {
    Kyber512,
}

// TODO templateize

pub mod kyber512 {
    use super::*;
    use pqcrypto::kem::kyber512;
    use pqcrypto::prelude::*;

    pub static ALGORITHM: agreement::Algorithm = agreement::Algorithm {
        algorithm: agreement::AlgorithmIdentifier::Kem(Algorithm::Kyber512),
        encapsulate: encapsulate,
        decapsulate: decapsulate,
        keypair: keypair,
    };

    fn encapsulate(peer_public_key: untrusted::Input, _rng: &rand::SecureRandom) -> Result<(agreement::Ciphertext, agreement::SharedSecret), error::Unspecified> {
        let pk = kyber512::PublicKey::from_bytes(peer_public_key.as_slice_less_safe()).map_err(|_| error::Unspecified)?;
        let (ct, ss) = kyber512::encapsulate(&pk);
        Ok((agreement::Ciphertext::new(ct.as_bytes().to_vec()), ss.as_bytes().to_vec()))
    }

    fn decapsulate(
        out: &mut [u8],
        private_key: &agreement::PrivateKey,
        ciphertext: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        if let agreement::PrivateKey::KemPrivateKey(private_key) = private_key {
            let ciphertext = kyber512::Ciphertext::from_bytes(ciphertext.as_slice_less_safe()).map_err(|_| error::Unspecified)?;
            let private_key = kyber512::SecretKey::from_bytes(private_key).map_err(|_| error::Unspecified)?;
            let ss = kyber512::decapsulate(&ciphertext, &private_key);
            out[..kyber512::shared_secret_bytes()].copy_from_slice(ss.as_bytes());
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }

    fn keypair(_rng: &rand::SecureRandom) -> Result<(agreement::PrivateKey, agreement::PublicKey), error::Unspecified> {
        let (pk, sk) = kyber512::keypair();
        Ok((agreement::PrivateKey::KemPrivateKey(sk.as_bytes().to_vec()),
            agreement::PublicKey::KemPublicKey(pk.as_bytes().to_vec())))
    }

}
