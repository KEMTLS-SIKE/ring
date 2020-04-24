use crate::{agreement, error, pkcs8, rand};
use untrusted;

pub use pqcrypto::traits::kem::PublicKey;

macro_rules! pqclean_kem_implementation {
    ($name: ident, $nametitle: ident, $namecaps: ident) => {
        pub mod $name {
            use super::*;
            use pqcrypto::{kem::$name as thekem, prelude::*};

            pub static ALGORITHM: agreement::Algorithm = agreement::Algorithm {
                algorithm: agreement::AlgorithmIdentifier::KEM,
                encapsulate,
                decapsulate,
                keypair,
            };

            fn encapsulate(
                peer_public_key: untrusted::Input,
                _rng: &rand::SecureRandom,
            ) -> Result<(agreement::Ciphertext, agreement::SharedSecret), error::Unspecified> {
                println!("Encapsulating with {}", stringify!($nametitle));
                let pk = $name::PublicKey::from_bytes(peer_public_key.as_slice_less_safe())
                    .map_err(|_| {
                        println!("From-bytes failed");
                        error::Unspecified
                    })?;
                let (ss, ct) = thekem::encapsulate(&pk);
                Ok((
                    agreement::Ciphertext::new(ct.as_bytes().to_vec()),
                    ss.as_bytes().to_vec(),
                ))
            }

            fn decapsulate(
                private_key: &agreement::PrivateKey,
                ciphertext: untrusted::Input,
            ) -> Result<Vec<u8>, error::Unspecified> {
                println!("Decapsulating with {}", stringify!($nametitle));
                if let agreement::PrivateKey::KemPrivateKey(private_key) = private_key {
                    debug_assert_eq!(ciphertext.len(), thekem::ciphertext_bytes());
                    let ciphertext =
                        thekem::Ciphertext::from_bytes(ciphertext.as_slice_less_safe())
                            .map_err(|_| error::Unspecified)?;
                    let private_key = thekem::SecretKey::from_bytes(private_key)
                        .map_err(|e| {
                            println!("{:#?}", e);
                            error::Unspecified
                        })?;
                    let ss = thekem::decapsulate(&ciphertext, &private_key);
                    Ok(ss.as_bytes().to_vec())
                } else {
                    println!("privatekey failed to unpack");
                    Err(error::Unspecified)
                }
            }

            fn keypair(
                _rng: &rand::SecureRandom,
            ) -> Result<(agreement::PrivateKey, agreement::PublicKey), error::Unspecified> {
                let (pk, sk) = thekem::keypair();
                Ok((
                    agreement::PrivateKey::KemPrivateKey(sk.as_bytes().to_vec()),
                    agreement::PublicKey::KemPublicKey(pk.as_bytes().to_vec()),
                ))
            }

        }

        pub use $name::ALGORITHM as $namecaps;

        #[cfg(test)]
        mod $nametitle {
            use super::*;
            use super::$namecaps as Kem;

            #[test]
            fn test_kem() -> Result<(), error::Unspecified>{
                let rng = rand::SystemRandom::new();
                let (sk, pk) = (Kem.keypair)(&rng)?;
                let (ct, ss) = (Kem.encapsulate)(untrusted::Input::from(pk.as_ref()), &rng)?;
                let ss2 = (Kem.decapsulate)(&sk, untrusted::Input::from(ct.as_ref()))?;
                assert_eq!(ss, ss2);
                Ok(())
            }
        }
    };
}

#[allow(unused)]
macro_rules! oqs_kem_implementation {
    ($name: ident, $nametitle: ident, $namecaps: ident) => {
        pub mod $name {
            use super::*;
            use oqs::kem;
            use lazy_static::lazy_static;

            pub static ALGORITHM: agreement::Algorithm = agreement::Algorithm {
                algorithm: agreement::AlgorithmIdentifier::KEM,
                encapsulate,
                decapsulate,
                keypair,
            };


            lazy_static! {
                static ref KEM: oqs::kem::Kem = {
                    kem::Kem::new(kem::Algorithm::$nametitle).unwrap()
                };
            }

            fn encapsulate(
                peer_public_key: untrusted::Input,
                _rng: &rand::SecureRandom,
            ) -> Result<(agreement::Ciphertext, agreement::SharedSecret), error::Unspecified> {
                let pk = KEM.public_key_from_bytes(peer_public_key.as_slice_less_safe());
                let (ct, ss) = KEM.encapsulate(&pk).unwrap();
                Ok((
                    agreement::Ciphertext::new(ct.into_vec()),
                    ss.into_vec(),
                ))
            }

            fn decapsulate(
                private_key: &agreement::PrivateKey,
                ciphertext: untrusted::Input,
            ) -> Result<Vec<u8>, error::Unspecified> {
                let sk = KEM.secret_key_from_bytes(private_key.as_bytes_less_safe());
                let ct = KEM.ciphertext_from_bytes(ciphertext.as_slice_less_safe());
                let ss = KEM.decapsulate(sk, ct).unwrap();
                Ok(ss.into_vec())
            }

            fn keypair(
                _rng: &rand::SecureRandom,
            ) -> Result<(agreement::PrivateKey, agreement::PublicKey), error::Unspecified> {
                let (pk, sk) = KEM.keypair().unwrap();
                Ok((
                    agreement::PrivateKey::KemPrivateKey(sk.into_vec()),
                    agreement::PublicKey::KemPublicKey(pk.into_vec()),
                ))
            }
        }

        pub use $name::ALGORITHM as $namecaps;

        #[cfg(test)]
        mod $nametitle {
            use super::*;
            use super::$namecaps as Kem;

            #[test]
            fn test_kem() -> Result<(), error::Unspecified>{
                let rng = rand::SystemRandom::new();
                let (sk, pk) = (Kem.keypair)(&rng)?;
                let (ct, ss) = (Kem.encapsulate)(untrusted::Input::from(pk.as_ref()), &rng)?;
                let ss2 = (Kem.decapsulate)(&sk, untrusted::Input::from(ct.as_ref()))?;
                assert_eq!(ss, ss2);
                Ok(())
            }
        }

    }
}

pqclean_kem_implementation!(kyber512, Kyber512, KYBER512);
pqclean_kem_implementation!(kyber768, Kyber768, KYBER768);
pqclean_kem_implementation!(kyber1024, Kyber1024, KYBER1024);
pqclean_kem_implementation!(kyber51290s, Kyber51290S, KYBER51290S);
pqclean_kem_implementation!(kyber76890s, Kyber76890S, KYBER76890S);
pqclean_kem_implementation!(kyber102490s, Kyber102490S, KYBER102490S);
pqclean_kem_implementation!(babybear, Babybear, BABYBEAR);
pqclean_kem_implementation!(babybearephem, Babybearephem, BABYBEAREPHEM);
pqclean_kem_implementation!(mamabear, Mamabear, MAMABEAR);
pqclean_kem_implementation!(mamabearephem, Mamabearephem, MAMABEAREPHEM);
pqclean_kem_implementation!(papabear, Papabear, PAPABEAR);
pqclean_kem_implementation!(papabearephem, Papabearephem, PAPABEAREPHEM);
pqclean_kem_implementation!(lightsaber, Lightsaber, LIGHTSABER);
pqclean_kem_implementation!(saber, Saber, SABER);
pqclean_kem_implementation!(firesaber, Firesaber, FIRESABER);
pqclean_kem_implementation!(ledakemlt12, Ledakemlt12, LEDAKEMLT12);
pqclean_kem_implementation!(ledakemlt32, Ledakemlt32, LEDAKEMLT32);
pqclean_kem_implementation!(ledakemlt52, Ledakemlt52, LEDAKEMLT52);
pqclean_kem_implementation!(newhope512cpa, Newhope512Cpa, NEWHOPE512CPA);
pqclean_kem_implementation!(newhope512cca, Newhope512Cca, NEWHOPE512CCA);
pqclean_kem_implementation!(newhope1024cpa, Newhope1024Cpa, NEWHOPE1024CPA);
pqclean_kem_implementation!(newhope1024cca, Newhope1024Cca, NEWHOPE1024CCA);
pqclean_kem_implementation!(ntruhps2048509, Ntruhps2048509, NTRUHPS2048509);
pqclean_kem_implementation!(ntruhps2048677, Ntruhps2048677, NTRUHPS2048677);
pqclean_kem_implementation!(ntruhps4096821, Ntruhps4096821, NTRUHPS4096821);
pqclean_kem_implementation!(ntruhrss701, Ntruhrss701, NTRUHRSS701);
pqclean_kem_implementation!(frodokem640aes, Frodokem640Aes, FRODOKEM640AES);
pqclean_kem_implementation!(frodokem640shake, Frodokem640Shake, FRODOKEM640SHAKE);
pqclean_kem_implementation!(frodokem976aes, Frodokem976Aes, FRODOKEM976AES);
pqclean_kem_implementation!(frodokem976shake, Frodokem976Shake, FRODOKEM976SHAKE);
pqclean_kem_implementation!(frodokem1344aes, Frodokem1344Aes, FRODOKEM1344AES);
pqclean_kem_implementation!(frodokem1344shake, Frodokem1344Shake, FRODOKEM1344SHAKE);
pqclean_kem_implementation!(mceliece348864, Mceliece348864, MCELIECE348864);
pqclean_kem_implementation!(mceliece348864f, Mceliece348864F, MCELIECE348864F);
pqclean_kem_implementation!(mceliece460896, Mceliece460896, MCELIECE460896);
pqclean_kem_implementation!(mceliece460896f, Mceliece460896F, MCELIECE460896F);
pqclean_kem_implementation!(mceliece6688128, Mceliece6688128, MCELIECE6688128);
pqclean_kem_implementation!(mceliece6688128f, Mceliece6688128F, MCELIECE6688128F);
pqclean_kem_implementation!(mceliece6960119, Mceliece6960119, MCELIECE6960119);
pqclean_kem_implementation!(mceliece6960119f, Mceliece6960119F, MCELIECE6960119F);
pqclean_kem_implementation!(mceliece8192128, Mceliece8192128, MCELIECE8192128);
pqclean_kem_implementation!(mceliece8192128f, Mceliece8192128F, MCELIECE8192128F);
pqclean_kem_implementation!(hqc1281cca2, Hqc1281Cca2, HQC1281CCA2);
pqclean_kem_implementation!(hqc1921cca2, Hqc1921Cca2, HQC1921CCA2);
pqclean_kem_implementation!(hqc1922cca2, Hqc1922Cca2, HQC1922CCA2);
pqclean_kem_implementation!(hqc2561cca2, Hqc2561Cca2, HQC2561CCA2);
pqclean_kem_implementation!(hqc2562cca2, Hqc2562Cca2, HQC2562CCA2);
pqclean_kem_implementation!(hqc2563cca2, Hqc2563Cca2, HQC2563CCA2);
oqs_kem_implementation!(bikel1fo, BikeL1Fo, BIKEL1FO);
oqs_kem_implementation!(sikep434compressed, SikeP434Compressed, SIKEP434COMPRESSED);


/// Generate the algorithm id for the algorithm
pub fn algorithm_to_id(alg: &agreement::Algorithm) -> u16 {
    if alg == &KYBER512 {
        101
    }
    else if alg == &KYBER768 {
        102
    }
    else if alg == &KYBER1024 {
        103
    }
    else if alg == &KYBER51290S {
        104
    }
    else if alg == &KYBER76890S {
        105
    }
    else if alg == &KYBER102490S {
        106
    }
    else if alg == &BABYBEAR {
        107
    }
    else if alg == &BABYBEAREPHEM {
        108
    }
    else if alg == &MAMABEAR {
        109
    }
    else if alg == &MAMABEAREPHEM {
        110
    }
    else if alg == &PAPABEAR {
        111
    }
    else if alg == &PAPABEAREPHEM {
        112
    }
    else if alg == &LIGHTSABER {
        113
    }
    else if alg == &SABER {
        114
    }
    else if alg == &FIRESABER {
        115
    }
    else if alg == &LEDAKEMLT12 {
        116
    }
    else if alg == &LEDAKEMLT32 {
        117
    }
    else if alg == &LEDAKEMLT52 {
        118
    }
    else if alg == &NEWHOPE512CPA {
        119
    }
    else if alg == &NEWHOPE512CCA {
        120
    }
    else if alg == &NEWHOPE1024CPA {
        121
    }
    else if alg == &NEWHOPE1024CCA {
        122
    }
    else if alg == &NTRUHPS2048509 {
        123
    }
    else if alg == &NTRUHPS2048677 {
        124
    }
    else if alg == &NTRUHPS4096821 {
        125
    }
    else if alg == &NTRUHRSS701 {
        126
    }
    else if alg == &FRODOKEM640AES {
        127
    }
    else if alg == &FRODOKEM640SHAKE {
        128
    }
    else if alg == &FRODOKEM976AES {
        129
    }
    else if alg == &FRODOKEM976SHAKE {
        130
    }
    else if alg == &FRODOKEM1344AES {
        131
    }
    else if alg == &FRODOKEM1344SHAKE {
        132
    }
    else if alg == &MCELIECE348864 {
        133
    }
    else if alg == &MCELIECE348864F {
        134
    }
    else if alg == &MCELIECE460896 {
        135
    }
    else if alg == &MCELIECE460896F {
        136
    }
    else if alg == &MCELIECE6688128 {
        137
    }
    else if alg == &MCELIECE6688128F {
        138
    }
    else if alg == &MCELIECE6960119 {
        139
    }
    else if alg == &MCELIECE6960119F {
        140
    }
    else if alg == &MCELIECE8192128 {
        141
    }
    else if alg == &MCELIECE8192128F {
        142
    }
    else if alg == &HQC1281CCA2 {
        143
    }
    else if alg == &HQC1921CCA2 {
        144
    }
    else if alg == &HQC1922CCA2 {
        145
    }
    else if alg == &HQC2561CCA2 {
        146
    }
    else if alg == &HQC2562CCA2 {
        147
    }
    else if alg == &HQC2563CCA2 {
        148
    }
    else if alg == &BIKEL1FO {
        149
    }
    else if alg == &SIKEP434COMPRESSED {
        150
    } else {
        unreachable!("Should not be reached")
    }
}

/*
/// Constructs the agreement private key from PKCS8.
fn private_key_from_pkcs8(
    alg: &agreement::Algorithm,
    id: u16,
    input: untrusted::Input,
) -> Result<agreement::PrivateKey, error::KeyRejected> {
    let mut template = b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02".to_vec();
    template.push((id as u16 >> 8) as u8);
    template.push(id as u8);
    // push null
    template.push(0x05);
    template.push(0);
    let (private_key, _) = pkcs8::unwrap_key_(&template, pkcs8::Version::V1OrV2, input)?;

    Ok(agreement::PrivateKey::from(alg, private_key))
}
*/
