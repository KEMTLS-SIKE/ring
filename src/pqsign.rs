//! Wraps the post-quantum signature schemes in something slightly more usable for Ring.
//!
//! Todo:
//! * Figure out desired API (probably steal from ECDSA/RSA)
//!     * Only RSA has PKCS1
//! * Import signature schemes from pqcrypto


pub use pqcrypto::traits::sign::{PublicKey, SecretKey, DetachedSignature};
pub use pqcrypto::sign::sphincsshake256128fsimple;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AlgorithmID {
    SPHINCS_SHAKE_256_128F_SIMPLE,
}

pub struct PQPublicKey {
    algorithm: AlgorithmID,
    key: Vec<u8>,
}

pub struct PQSecretKey {
    algorithm: AlgorithmID,
    key: Vec<u8>
}

pub struct PQSignature {
    algorithm: AlgorithmID,
    signature: Vec<u8>,
}

pub struct PQSignatureScheme {

    pub keygen: fn() -> (PQPublicKey, PQSecretKey),

    pub sign: fn(&[u8], &PQSecretKey) -> PQSignature,

    pub algorithm: AlgorithmID,

    pub verify: for<'a, 'b, 'c> fn(&'a [u8], &'b PQSignature, &'c PQPublicKey) -> bool,

}

#[allow(unused)]
pub static SPHINCS_SHAKE_256_128F_SIMPLE: PQSignatureScheme = PQSignatureScheme {
    algorithm: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
    keygen: || {
        let (pk, sk) = sphincsshake256128fsimple::keypair();
        let pqpk = PQPublicKey {
            algorithm: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
            key: pk.as_bytes().to_vec(),
        };
        let pqsk = PQSecretKey {
            algorithm: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
            key: sk.as_bytes().to_vec(),
        };
        (pqpk, pqsk)
    },

    sign: |message: &[u8], sk: &PQSecretKey| {
        debug_assert_eq!(sk.algorithm, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        let sk = sphincsshake256128fsimple::SecretKey::from_bytes(&sk.key);
        let sig = sphincsshake256128fsimple::detached_sign(message, &sk);
        PQSignature {
            algorithm: AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE,
            signature: sig.as_bytes().to_vec(),
        }
    },
    verify: |message: &[u8], sig: &PQSignature, pk: &PQPublicKey| {
        debug_assert_eq!(pk.algorithm, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        debug_assert_eq!(sig.algorithm, AlgorithmID::SPHINCS_SHAKE_256_128F_SIMPLE);
        let sig = sphincsshake256128fsimple::DetachedSignature::from_bytes(&sig.signature);
        let pk = sphincsshake256128fsimple::PublicKey::from_bytes(&pk.key);
        sphincsshake256128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
    }
};

