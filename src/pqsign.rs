//! Wraps the post-quantum signature schemes in something slightly more usable
//! for Ring.
//!
//! Todo:
//! * Figure out desired API (probably steal from ECDSA/RSA)
//!     * Only RSA has PKCS1
//! * Import signature schemes from pqcrypto

use pqcrypto::prelude::*;

use crate::{error, pkcs8, sealed, signature};
use untrusted;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AlgorithmID {
    SPHINCS_SHA_256_128S_SIMPLE = 0xFE00,
    SPHINCS_SHA_256_128S_ROBUST = 0xFE01,
    SPHINCS_SHA_256_128F_SIMPLE = 0xFE02,
    SPHINCS_SHA_256_128F_ROBUST = 0xFE03,
    SPHINCS_SHA_256_192S_SIMPLE = 0xFE04,
    SPHINCS_SHA_256_192S_ROBUST = 0xFE05,
    SPHINCS_SHA_256_192F_SIMPLE = 0xFE06,
    SPHINCS_SHA_256_192F_ROBUST = 0xFE07,
    SPHINCS_SHA_256_256S_SIMPLE = 0xFE08,
    SPHINCS_SHA_256_256S_ROBUST = 0xFE09,
    SPHINCS_SHA_256_256F_SIMPLE = 0xFE0A,
    SPHINCS_SHA_256_256F_ROBUST = 0xFE0B,
    SPHINCS_SHAKE_256_128S_SIMPLE = 0xFE0C,
    SPHINCS_SHAKE_256_128S_ROBUST = 0xFE0D,
    SPHINCS_SHAKE_256_128F_SIMPLE = 0xFE0E,
    SPHINCS_SHAKE_256_128F_ROBUST = 0xFE0F,
    SPHINCS_SHAKE_256_192S_SIMPLE = 0xFE10,
    SPHINCS_SHAKE_256_192S_ROBUST = 0xFE11,
    SPHINCS_SHAKE_256_192F_SIMPLE = 0xFE12,
    SPHINCS_SHAKE_256_192F_ROBUST = 0xFE13,
    SPHINCS_SHAKE_256_256S_SIMPLE = 0xFE14,
    SPHINCS_SHAKE_256_256S_ROBUST = 0xFE15,
    SPHINCS_SHAKE_256_256F_SIMPLE = 0xFE16,
    SPHINCS_SHAKE_256_256F_ROBUST = 0xFE17,
    SPHINCS_HARAKA_128S_SIMPLE = 0xFE18,
    SPHINCS_HARAKA_128S_ROBUST = 0xFE19,
    SPHINCS_HARAKA_128F_SIMPLE = 0xFE1A,
    SPHINCS_HARAKA_128F_ROBUST = 0xFE1B,
    SPHINCS_HARAKA_192S_SIMPLE = 0xFE1C,
    SPHINCS_HARAKA_192S_ROBUST = 0xFE1D,
    SPHINCS_HARAKA_192F_SIMPLE = 0xFE1E,
    SPHINCS_HARAKA_192F_ROBUST = 0xFE1F,
    SPHINCS_HARAKA_256S_SIMPLE = 0xFE20,
    SPHINCS_HARAKA_256S_ROBUST = 0xFE21,
    SPHINCS_HARAKA_256F_SIMPLE = 0xFE22,
    SPHINCS_HARAKA_256F_ROBUST = 0xFE23,
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
        let mut template = b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02".to_vec();
        template.push((alg.id as u16 >> 8) as u8);
        template.push(alg.id as u8);
        // push null
        template.push(0x05);
        template.push(0);
        let (private_key, _) = pkcs8::unwrap_key_(&template, pkcs8::Version::V1OrV2, input)?;


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

    pub verify: for<'a, 'b, 'c> fn(
        &'a [u8],
        &'b PQSignature,
        &'c PQPublicKey,
    ) -> Result<(), Box<dyn std::error::Error>>,

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

        {
            use std::io::prelude::*;
            use std::fs::File;
            let mut f = File::create("/tmp/msg.bin").unwrap();
            f.write_all(msg.as_slice_less_safe()).unwrap();
        }

        if let Ok(()) = (self.verify)(msg.as_slice_less_safe(), &sig, &pk) {
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }
}

macro_rules! sphincs_scheme {
    ($id: ident, $ns: ident) => {
        use pqcrypto::sign::$ns;
        pub static $id: PQSignatureScheme = PQSignatureScheme {
            id: AlgorithmID::$id,
            keypair: || {
                let (pk, sk) = $ns::keypair();
                let pqpk = PQPublicKey {
                    alg: &$id,
                    key: pk.as_bytes().to_vec(),
                };
                let pqsk = PQSecretKey {
                    alg: &$id,
                    key: sk.as_bytes().to_vec(),
                };
                PQKeyPair { pk: pqpk, sk: pqsk }
            },
            pk_from_slice: |pk: &[u8]| PQPublicKey {
                alg: &$id,
                key: pk.to_vec(),
            },
            sk_from_slice: |sk: &[u8]| PQSecretKey {
                alg: &$id,
                key: sk.to_vec(),
            },
            sign: |message: &[u8], sk: &PQSecretKey| {
                debug_assert_eq!(sk.alg.id, AlgorithmID::$id);
                let sk = $ns::SecretKey::from_bytes(&sk.key).unwrap();
                let sig = $ns::detached_sign(message, &sk);
                PQSignature {
                    id: AlgorithmID::$id,
                    signature: sig.as_bytes().to_vec(),
                }
            },
            verify: |message: &[u8], sig: &PQSignature, pk: &PQPublicKey| {
                debug_assert_eq!(pk.alg.id, AlgorithmID::$id);
                debug_assert_eq!(sig.id, AlgorithmID::$id);
                let sig = $ns::DetachedSignature::from_bytes(&sig.signature)?;
                let pk = $ns::PublicKey::from_bytes(&pk.key)?;
                $ns::verify_detached_signature(&sig, message, &pk)?;
                Ok(())
            },
        };
    };
}

sphincs_scheme!(SPHINCS_SHA_256_128S_SIMPLE, sphincssha256128ssimple);
sphincs_scheme!(SPHINCS_SHA_256_128S_ROBUST, sphincssha256128srobust);
sphincs_scheme!(SPHINCS_SHA_256_128F_SIMPLE, sphincssha256128fsimple);
sphincs_scheme!(SPHINCS_SHA_256_128F_ROBUST, sphincssha256128frobust);
sphincs_scheme!(SPHINCS_SHA_256_192S_SIMPLE, sphincssha256192ssimple);
sphincs_scheme!(SPHINCS_SHA_256_192S_ROBUST, sphincssha256192srobust);
sphincs_scheme!(SPHINCS_SHA_256_192F_SIMPLE, sphincssha256192fsimple);
sphincs_scheme!(SPHINCS_SHA_256_192F_ROBUST, sphincssha256192frobust);
sphincs_scheme!(SPHINCS_SHA_256_256S_SIMPLE, sphincssha256256ssimple);
sphincs_scheme!(SPHINCS_SHA_256_256S_ROBUST, sphincssha256256srobust);
sphincs_scheme!(SPHINCS_SHA_256_256F_SIMPLE, sphincssha256256fsimple);
sphincs_scheme!(SPHINCS_SHA_256_256F_ROBUST, sphincssha256256frobust);
sphincs_scheme!(SPHINCS_SHAKE_256_128S_SIMPLE, sphincsshake256128ssimple);
sphincs_scheme!(SPHINCS_SHAKE_256_128S_ROBUST, sphincsshake256128srobust);
sphincs_scheme!(SPHINCS_SHAKE_256_128F_SIMPLE, sphincsshake256128fsimple);
sphincs_scheme!(SPHINCS_SHAKE_256_128F_ROBUST, sphincsshake256128frobust);
sphincs_scheme!(SPHINCS_SHAKE_256_192S_SIMPLE, sphincsshake256192ssimple);
sphincs_scheme!(SPHINCS_SHAKE_256_192S_ROBUST, sphincsshake256192srobust);
sphincs_scheme!(SPHINCS_SHAKE_256_192F_SIMPLE, sphincsshake256192fsimple);
sphincs_scheme!(SPHINCS_SHAKE_256_192F_ROBUST, sphincsshake256192frobust);
sphincs_scheme!(SPHINCS_SHAKE_256_256S_SIMPLE, sphincsshake256256ssimple);
sphincs_scheme!(SPHINCS_SHAKE_256_256S_ROBUST, sphincsshake256256srobust);
sphincs_scheme!(SPHINCS_SHAKE_256_256F_SIMPLE, sphincsshake256256fsimple);
sphincs_scheme!(SPHINCS_SHAKE_256_256F_ROBUST, sphincsshake256256frobust);
sphincs_scheme!(SPHINCS_HARAKA_128S_SIMPLE, sphincsharaka128ssimple);
sphincs_scheme!(SPHINCS_HARAKA_128S_ROBUST, sphincsharaka128srobust);
sphincs_scheme!(SPHINCS_HARAKA_128F_SIMPLE, sphincsharaka128fsimple);
sphincs_scheme!(SPHINCS_HARAKA_128F_ROBUST, sphincsharaka128frobust);
sphincs_scheme!(SPHINCS_HARAKA_192S_SIMPLE, sphincsharaka192ssimple);
sphincs_scheme!(SPHINCS_HARAKA_192S_ROBUST, sphincsharaka192srobust);
sphincs_scheme!(SPHINCS_HARAKA_192F_SIMPLE, sphincsharaka192fsimple);
sphincs_scheme!(SPHINCS_HARAKA_192F_ROBUST, sphincsharaka192frobust);
sphincs_scheme!(SPHINCS_HARAKA_256S_SIMPLE, sphincsharaka256ssimple);
sphincs_scheme!(SPHINCS_HARAKA_256S_ROBUST, sphincsharaka256srobust);
sphincs_scheme!(SPHINCS_HARAKA_256F_SIMPLE, sphincsharaka256fsimple);
sphincs_scheme!(SPHINCS_HARAKA_256F_ROBUST, sphincsharaka256frobust);

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
        assert!((scheme.verify)(&message, &sig, &keypair.pk).is_ok());
        message[10] = 1;
        assert!(!(scheme.verify)(&message, &sig, &keypair.pk).is_ok());
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
