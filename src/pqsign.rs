//! Wraps the post-quantum signature schemes in something slightly more usable
//! for Ring.

use ::oqs::sig as oqs;

use crate::{error, pkcs8, sealed, signature};
use crate::io::der;
use xmss_rs as xmss;
use untrusted;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AlgorithmID {
    DILITHIUM2 = 0xFE00,
    DILITHIUM3 = 0xFE01,
    DILITHIUM4 = 0xFE02,
    FALCON512 = 0xFE03,
    FALCON1024 = 0xFE04,
    MQDSS3148 = 0xFE05,
    MQDSS3164 = 0xFE06,
    RAINBOW_IA_CLASSIC = 0xFE07,
    RAINBOW_IA_CYCLIC = 0xFE08,
    RAINBOW_IA_CYCLIC_COMPRESSED = 0xFE09,
    RAINBOW_II_ICCLASSIC = 0xFE0A,
    RAINBOW_II_IC_CYCLIC = 0xFE0B,
    RAINBOW_II_IC_CYCLIC_COMPRESSED = 0xFE0C,
    RAINBOW_VC_CLASSIC = 0xFE0D,
    RAINBOW_VC_CYCLIC = 0xFE0E,
    RAINBOW_VC_CYCLIC_COMPRESSED = 0xFE0F,
    SPHINCS_HARAKA128F_ROBUST = 0xFE10,
    SPHINCS_HARAKA128F_SIMPLE = 0xFE11,
    SPHINCS_HARAKA128S_ROBUST = 0xFE12,
    SPHINCS_HARAKA128S_SIMPLE = 0xFE13,
    SPHINCS_HARAKA192F_ROBUST = 0xFE14,
    SPHINCS_HARAKA192F_SIMPLE = 0xFE15,
    SPHINCS_HARAKA192S_ROBUST = 0xFE16,
    SPHINCS_HARAKA192S_SIMPLE = 0xFE17,
    SPHINCS_HARAKA256F_ROBUST = 0xFE18,
    SPHINCS_HARAKA256F_SIMPLE = 0xFE19,
    SPHINCS_HARAKA256S_ROBUST = 0xFE1A,
    SPHINCS_HARAKA256S_SIMPLE = 0xFE1B,
    SPHINCS_SHA256128F_ROBUST = 0xFE1C,
    SPHINCS_SHA256128F_SIMPLE = 0xFE1D,
    SPHINCS_SHA256128S_ROBUST = 0xFE1E,
    SPHINCS_SHA256128S_SIMPLE = 0xFE1F,
    SPHINCS_SHA256192F_ROBUST = 0xFE20,
    SPHINCS_SHA256192F_SIMPLE = 0xFE21,
    SPHINCS_SHA256192S_ROBUST = 0xFE22,
    SPHINCS_SHA256192S_SIMPLE = 0xFE23,
    SPHINCS_SHA256256F_ROBUST = 0xFE24,
    SPHINCS_SHA256256F_SIMPLE = 0xFE25,
    SPHINCS_SHA256256S_ROBUST = 0xFE26,
    SPHINCS_SHA256256S_SIMPLE = 0xFE27,
    SPHINCS_SHAKE256128F_ROBUST = 0xFE28,
    SPHINCS_SHAKE256128F_SIMPLE = 0xFE29,
    SPHINCS_SHAKE256128S_ROBUST = 0xFE2A,
    SPHINCS_SHAKE256128S_SIMPLE = 0xFE2B,
    SPHINCS_SHAKE256192F_ROBUST = 0xFE2C,
    SPHINCS_SHAKE256192F_SIMPLE = 0xFE2D,
    SPHINCS_SHAKE256192S_ROBUST = 0xFE2E,
    SPHINCS_SHAKE256192S_SIMPLE = 0xFE2F,
    SPHINCS_SHAKE256256F_ROBUST = 0xFE30,
    SPHINCS_SHAKE256256F_SIMPLE = 0xFE31,
    SPHINCS_SHAKE256256S_ROBUST = 0xFE32,
    SPHINCS_SHAKE256256S_SIMPLE = 0xFE33,
    PICNIC_L1_FS = 0xFE34,
    PICNIC_L1_UR = 0xFE35,
    PICNIC_L3_FS = 0xFE36,
    PICNIC_L3_UR = 0xFE37,
    PICNIC_L5_FS = 0xFE38,
    PICNIC_L5_UR = 0xFE39,
    PICNIC2_L1_FS = 0xFE3A,
    PICNIC2_L3_FS = 0xFE3B,
    PICNIC2_L5_FS = 0xFE3C,
    Q_TESLA_PI = 0xFE3D,
    Q_TESLA_PIII = 0xFE3E,
    XMSS = 0xFE3F,
    GEMSS128 = 0xFE40,
}

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
        let (private_key, _) = pkcs8::unwrap_key_(&template, pkcs8::Version::V1OrV2, input)?;

        let private_key = private_key.read_all(error::KeyRejected::invalid_encoding(), |input| {
            der::expect_tag_and_get_value(input, der::Tag::OctetString)
                .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())
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

        if let Ok(()) = (self.verify)(msg.as_slice_less_safe(), &sig, &pk) {
            Ok(())
        } else {
            Err(error::Unspecified)
        }
    }
}

macro_rules! pqsig_scheme {
    ($id: ident, $alg: ident) => {
        pub static $id: PQSignatureScheme = PQSignatureScheme {
            id: AlgorithmID::$id,
            keypair: || {
                let alg = oqs::Sig::new(oqs::Algorithm::$alg).unwrap();
                let (pk, sk) = alg.keypair().unwrap();
                let pqpk = PQPublicKey {
                    alg: &$id,
                    key: pk.into_vec(),
                };
                let pqsk = PQSecretKey {
                    alg: &$id,
                    key: sk.into_vec(),
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
                let alg = oqs::Sig::new(oqs::Algorithm::$alg).unwrap();
                let sk = alg.secret_key_from_bytes(&sk.key);
                let sig = alg.sign(message, sk).unwrap();
                PQSignature {
                    id: AlgorithmID::$id,
                    signature: sig.into_vec(),
                }
            },
            verify: |message: &[u8], sig: &PQSignature, pk: &PQPublicKey| {
                debug_assert_eq!(pk.alg.id, AlgorithmID::$id);
                debug_assert_eq!(sig.id, AlgorithmID::$id);
                let alg = oqs::Sig::new(oqs::Algorithm::$alg).unwrap();
                let sig = alg.signature_from_bytes(&sig.signature);
                let pk = alg.public_key_from_bytes(&pk.key);
                alg.verify(message, sig, pk)?;
                Ok(())
            },
        };
    };
}

pub static XMSS: PQSignatureScheme = PQSignatureScheme {
    id: AlgorithmID::XMSS,
    keypair: || {
        let (pk, sk) = xmss::keypair();
        let pk = (XMSS.pk_from_slice)(&pk);
        let sk = (XMSS.sk_from_slice)(&sk);
        PQKeyPair { pk, sk }
    },
    pk_from_slice: |pk: &[u8]| PQPublicKey {
        alg: &XMSS,
        key: pk.to_vec(),
    },
    sk_from_slice: |sk: &[u8]| PQSecretKey {
        alg: &XMSS,
        key: sk.to_vec(),
    },
    sign: |_message: &[u8], _sk: &PQSecretKey| {
        panic!("Not supported for XMSS due to necessary mut sk");
    },
    verify: |message: &[u8], sig: &PQSignature, pk: &PQPublicKey| {
        debug_assert_eq!(pk.alg.id, AlgorithmID::XMSS);
        debug_assert_eq!(sig.id, AlgorithmID::XMSS);
        if xmss_rs::verify(message, &sig.signature, &pk.key) {
            Ok(())
        } else {
            Err(Box::new(error::Unspecified))
        }
    }
};


pqsig_scheme!(DILITHIUM2, Dilithium2);
pqsig_scheme!(DILITHIUM3, Dilithium3);
pqsig_scheme!(DILITHIUM4, Dilithium4);
pqsig_scheme!(FALCON512, Falcon512);
pqsig_scheme!(FALCON1024, Falcon1024);
pqsig_scheme!(MQDSS3148, MQDSS3148);
pqsig_scheme!(MQDSS3164, MQDSS3164);
pqsig_scheme!(RAINBOW_IA_CLASSIC, RainbowIaClassic);
pqsig_scheme!(RAINBOW_IA_CYCLIC, RainbowIaCyclic);
pqsig_scheme!(RAINBOW_IA_CYCLIC_COMPRESSED, RainbowIaCyclicCompressed);
pqsig_scheme!(RAINBOW_II_ICCLASSIC, RainbowIIIcclassic);
pqsig_scheme!(RAINBOW_II_IC_CYCLIC, RainbowIIIcCyclic);
pqsig_scheme!(RAINBOW_II_IC_CYCLIC_COMPRESSED, RainbowIIIcCyclicCompressed);
pqsig_scheme!(RAINBOW_VC_CLASSIC, RainbowVcClassic);
pqsig_scheme!(RAINBOW_VC_CYCLIC, RainbowVcCyclic);
pqsig_scheme!(RAINBOW_VC_CYCLIC_COMPRESSED, RainbowVcCyclicCompressed);
pqsig_scheme!(SPHINCS_HARAKA128F_ROBUST, SphincsHaraka128fRobust);
pqsig_scheme!(SPHINCS_HARAKA128F_SIMPLE, SphincsHaraka128fSimple);
pqsig_scheme!(SPHINCS_HARAKA128S_ROBUST, SphincsHaraka128sRobust);
pqsig_scheme!(SPHINCS_HARAKA128S_SIMPLE, SphincsHaraka128sSimple);
pqsig_scheme!(SPHINCS_HARAKA192F_ROBUST, SphincsHaraka192fRobust);
pqsig_scheme!(SPHINCS_HARAKA192F_SIMPLE, SphincsHaraka192fSimple);
pqsig_scheme!(SPHINCS_HARAKA192S_ROBUST, SphincsHaraka192sRobust);
pqsig_scheme!(SPHINCS_HARAKA192S_SIMPLE, SphincsHaraka192sSimple);
pqsig_scheme!(SPHINCS_HARAKA256F_ROBUST, SphincsHaraka256fRobust);
pqsig_scheme!(SPHINCS_HARAKA256F_SIMPLE, SphincsHaraka256fSimple);
pqsig_scheme!(SPHINCS_HARAKA256S_ROBUST, SphincsHaraka256sRobust);
pqsig_scheme!(SPHINCS_HARAKA256S_SIMPLE, SphincsHaraka256sSimple);
pqsig_scheme!(SPHINCS_SHA256128F_ROBUST, SphincsSha256128fRobust);
pqsig_scheme!(SPHINCS_SHA256128F_SIMPLE, SphincsSha256128fSimple);
pqsig_scheme!(SPHINCS_SHA256128S_ROBUST, SphincsSha256128sRobust);
pqsig_scheme!(SPHINCS_SHA256128S_SIMPLE, SphincsSha256128sSimple);
pqsig_scheme!(SPHINCS_SHA256192F_ROBUST, SphincsSha256192fRobust);
pqsig_scheme!(SPHINCS_SHA256192F_SIMPLE, SphincsSha256192fSimple);
pqsig_scheme!(SPHINCS_SHA256192S_ROBUST, SphincsSha256192sRobust);
pqsig_scheme!(SPHINCS_SHA256192S_SIMPLE, SphincsSha256192sSimple);
pqsig_scheme!(SPHINCS_SHA256256F_ROBUST, SphincsSha256256fRobust);
pqsig_scheme!(SPHINCS_SHA256256F_SIMPLE, SphincsSha256256fSimple);
pqsig_scheme!(SPHINCS_SHA256256S_ROBUST, SphincsSha256256sRobust);
pqsig_scheme!(SPHINCS_SHA256256S_SIMPLE, SphincsSha256256sSimple);
pqsig_scheme!(SPHINCS_SHAKE256128F_ROBUST, SphincsShake256128fRobust);
pqsig_scheme!(SPHINCS_SHAKE256128F_SIMPLE, SphincsShake256128fSimple);
pqsig_scheme!(SPHINCS_SHAKE256128S_ROBUST, SphincsShake256128sRobust);
pqsig_scheme!(SPHINCS_SHAKE256128S_SIMPLE, SphincsShake256128sSimple);
pqsig_scheme!(SPHINCS_SHAKE256192F_ROBUST, SphincsShake256192fRobust);
pqsig_scheme!(SPHINCS_SHAKE256192F_SIMPLE, SphincsShake256192fSimple);
pqsig_scheme!(SPHINCS_SHAKE256192S_ROBUST, SphincsShake256192sRobust);
pqsig_scheme!(SPHINCS_SHAKE256192S_SIMPLE, SphincsShake256192sSimple);
pqsig_scheme!(SPHINCS_SHAKE256256F_ROBUST, SphincsShake256256fRobust);
pqsig_scheme!(SPHINCS_SHAKE256256F_SIMPLE, SphincsShake256256fSimple);
pqsig_scheme!(SPHINCS_SHAKE256256S_ROBUST, SphincsShake256256sRobust);
pqsig_scheme!(SPHINCS_SHAKE256256S_SIMPLE, SphincsShake256256sSimple);
pqsig_scheme!(PICNIC_L1_FS, PicnicL1Fs);
pqsig_scheme!(PICNIC_L1_UR, PicnicL1Ur);
pqsig_scheme!(PICNIC_L3_FS, PicnicL3Fs);
pqsig_scheme!(PICNIC_L3_UR, PicnicL3Ur);
pqsig_scheme!(PICNIC_L5_FS, PicnicL5Fs);
pqsig_scheme!(PICNIC_L5_UR, PicnicL5Ur);
pqsig_scheme!(PICNIC2_L1_FS, Picnic2L1Fs);
pqsig_scheme!(PICNIC2_L3_FS, Picnic2L3Fs);
pqsig_scheme!(PICNIC2_L5_FS, Picnic2L5Fs);
pqsig_scheme!(Q_TESLA_PI, QTeslaPI);
pqsig_scheme!(Q_TESLA_PIII, QTeslaPIII);
pqsig_scheme!(GEMSS128, Gemss128);

#[cfg(test)]
mod tests {

    use super::*;
    use crate::signature;
    use untrusted::Input;

    #[test]
    fn test_signatures_scheme_sphincs_shake_256_128f_simple() {
        let scheme = &SPHINCS_SHAKE256128F_SIMPLE;

        let mut message = [0u8; 64];
        let keypair = (scheme.keypair)();
        let sig = (scheme.sign)(&message, &keypair.sk);
        assert!((scheme.verify)(&message, &sig, &keypair.pk).is_ok());
        message[10] = 1;
        assert!(!(scheme.verify)(&message, &sig, &keypair.pk).is_ok());
    }

    #[test]
    fn test_pqsecretkey() {
        let scheme = &SPHINCS_SHAKE256128F_SIMPLE;

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
