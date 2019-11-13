use crate::{agreement, error, pkcs8, rand};
use untrusted;

pub use pqcrypto::traits::kem::PublicKey;

macro_rules! kem_implementation {
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
                let pk = $name::PublicKey::from_bytes(peer_public_key.as_slice_less_safe())
                    .map_err(|_| error::Unspecified)?;
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
                if let agreement::PrivateKey::KemPrivateKey(private_key) = private_key {
                    debug_assert_eq!(ciphertext.len(), thekem::ciphertext_bytes());
                    let ciphertext =
                        thekem::Ciphertext::from_bytes(ciphertext.as_slice_less_safe())
                            .map_err(|_| error::Unspecified)?;
                    let private_key = thekem::SecretKey::from_bytes(private_key)
                        .map_err(|_| error::Unspecified)?;
                    let ss = thekem::decapsulate(&ciphertext, &private_key);
                    Ok(ss.as_bytes().to_vec())
                } else {
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
    };
}

kem_implementation!(kyber512, Kyber512, KYBER512);
kem_implementation!(kyber768, Kyber768, KYBER768);
kem_implementation!(kyber1024, Kyber1024, KYBER1024);
kem_implementation!(kyber51290s, Kyber51290s, KYBER51290S);
kem_implementation!(kyber76890s, Kyber76890s, KYBER76890S);
kem_implementation!(kyber102490s, Kyber102490s, KYBER102490S);
kem_implementation!(babybear, Babybear, BABYBEAR);
kem_implementation!(mamabear, Mamabear, MAMABEAR);
kem_implementation!(papabear, Papabear, PAPABEAR);
kem_implementation!(lightsaber, Lightsaber, LIGHTSABER);
kem_implementation!(saber, Saber, SABER);
kem_implementation!(firesaber, Firesaber, FIRESABER);
kem_implementation!(ledakemlt12, Ledakemlt12, LEDAKEMLT12);
kem_implementation!(ledakemlt32, Ledakemlt32, LEDAKEMLT32);
kem_implementation!(ledakemlt52, Ledakemlt52, LEDAKEMLT52);
kem_implementation!(newhope512cpa, Newhope512Cpa, NEWHOPE512CPA);
kem_implementation!(newhope512cca, Newhope512Cca, NEWHOPE512CCA);
kem_implementation!(newhope1024cpa, Newhope1024Cpa, NEWHOPE1024CPA);
kem_implementation!(newhope1024cca, Newhope1024Cca, NEWHOPE1024CCA);
kem_implementation!(ntruhps2048509, Ntruhps2048509, NTRUHPS2048509);
kem_implementation!(ntruhps2048677, Ntruhps2048677, NTRUHPS2048677);
kem_implementation!(ntruhps4096821, Ntruhps4096821, NTRUHPS4096821);
kem_implementation!(ntruhrss701, Ntruhrss701, NTRUHRSS701);
kem_implementation!(frodokem640aes, Frodokem640Aes, FRODOKEM640AES);
kem_implementation!(frodokem640shake, Frodokem640Shake, FRODOKEM640SHAKE);
kem_implementation!(frodokem976aes, Frodokem976Aes, FRODOKEM976AES);
kem_implementation!(frodokem976shake, Frodokem976Shake, FRODOKEM976SHAKE);
kem_implementation!(frodokem1344aes, Frodokem1344Aes, FRODOKEM1344AES);
kem_implementation!(frodokem1344shake, Frodokem1344Shake, FRODOKEM1344SHAKE);

/// Generate the algorithm id for the algorithm
pub fn algorithm_to_id(alg: &agreement::Algorithm) -> u16 {
    if alg == &KYBER512 {
        101
    } else if alg == &KYBER768 {
        102
    } else if alg == &KYBER1024 {
        103
    } else if alg == &KYBER51290S {
        104
    } else if alg == &KYBER76890S {
        105
    } else if alg == &KYBER102490S {
        106
    } else if alg == &BABYBEAR {
        107
    } else if alg == &MAMABEAR {
        108
    } else if alg == &PAPABEAR {
        109
    } else if alg == &LIGHTSABER {
        110
    } else if alg == &SABER {
        111
    } else if alg == &FIRESABER {
        112
    } else if alg == &LEDAKEMLT12 {
        113
    } else if alg == &LEDAKEMLT32 {
        114
    } else if alg == &LEDAKEMLT52 {
        115
    } else if alg == &NEWHOPE512CPA {
        116
    } else if alg == &NEWHOPE512CCA {
        117
    } else if alg == &NEWHOPE1024CPA {
        118
    } else if alg == &NEWHOPE1024CCA {
        119
    } else if alg == &NTRUHPS2048509 {
        120
    } else if alg == &NTRUHPS2048677 {
        121
    } else if alg == &NTRUHPS4096821 {
        122
    } else if alg == &NTRUHRSS701 {
        123
    } else if alg == &FRODOKEM640AES {
        124
    } else if alg == &FRODOKEM640SHAKE {
        125
    } else if alg == &FRODOKEM976AES {
        126
    } else if alg == &FRODOKEM976SHAKE {
        127
    } else if alg == &FRODOKEM1344AES {
        128
    } else if alg == &FRODOKEM1344SHAKE {
        129
    } else {
        unreachable!("Should not be reached")
    }
}

/// Constructs the agreement private key from PKCS8.
pub fn private_key_from_pkcs8(
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
