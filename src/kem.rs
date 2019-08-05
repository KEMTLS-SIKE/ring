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

/// Generate the algorithm id for the algorithm
pub fn algorithm_to_id(alg: &agreement::Algorithm) -> u16 {
    if alg == &KYBER512 {
        101
    } else if alg == &KYBER768 {
        102
    } else if alg == &KYBER1024 {
        103
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
