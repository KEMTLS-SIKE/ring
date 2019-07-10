use crate::{agreement, ec, error, rand};

use csidh_rust;

static CURVE_CSIDH: ec::Curve = ec::Curve {
    public_key_len: csidh_rust::PUBLIC_KEY_LEN,
    elem_scalar_seed_len: csidh_rust::PRIVATE_KEY_LEN,
    id: ec::CurveID::CSIDH,
    check_private_key_bytes: csidh_check_private_key_bytes,
    generate_private_key: csidh_generate_private_key,
    public_from_private: csidh_public_from_private,
};

fn csidh_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    debug_assert_eq!(bytes.len(), csidh_rust::PRIVATE_KEY_LEN);
    Ok(())
}

fn csidh_generate_private_key(
    _rng: &rand::SecureRandom,
    out: &mut [u8],
) -> Result<(), error::Unspecified> {
    let sk = csidh_rust::CSIDHPrivateKey::generate();
    out[..csidh_rust::PRIVATE_KEY_LEN].copy_from_slice(sk.as_slice());
    Ok(())
}

fn seed_to_private(seed: &ec::Seed) -> csidh_rust::CSIDHPrivateKey {
    csidh_rust::CSIDHPrivateKey::from_bytes(seed.bytes_less_safe())
}

fn csidh_public_from_private(
    public_out: &mut [u8],
    private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    let sk = seed_to_private(private_key);
    let pk = csidh_rust::CSIDHPublicKey::from_private(&sk);
    public_out[..csidh_rust::PUBLIC_KEY_LEN].copy_from_slice(pk.as_slice());
    Ok(())
}

pub static CSIDH: agreement::Algorithm = agreement::Algorithm {
    algorithm: agreement::AlgorithmIdentifier::Curve(&CURVE_CSIDH),
    encapsulate: encapsulate,
    decapsulate: csidh_ecdh,
    keypair: csidh_keypair,
};

fn csidh_keypair(rng: &dyn rand::SecureRandom) -> Result<(agreement::PrivateKey, agreement::PublicKey), error::Unspecified> {
    let cpu_features = crate::cpu::features();
    let sk = ec::Seed::generate(&CURVE_CSIDH, rng, cpu_features)?;
    let pk = Box::new(sk.compute_public_key()?);

    Ok((agreement::PrivateKey::ECPrivateKey(Box::new(sk)), agreement::PublicKey::ECPublicKey(pk)))
}

fn encapsulate(peer_public_key: untrusted::Input, _rng: &rand::SecureRandom) -> Result<(agreement::Ciphertext, agreement::SharedSecret), error::Unspecified>{
    let sk = csidh_rust::CSIDHPrivateKey::generate();
    let pk = csidh_rust::CSIDHPublicKey::from_private(&sk);
    let peer_pk = csidh_rust::CSIDHPublicKey::from_bytes(peer_public_key.as_slice_less_safe());
    Ok((agreement::Ciphertext::new(pk.as_slice().to_vec()), csidh_rust::agreement(&peer_pk, &sk).to_vec()))
}

fn csidh_ecdh(
    out: &mut [u8],
    my_private_key: &agreement::PrivateKey,
    peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    if let agreement::PrivateKey::ECPrivateKey(my_private_key) = my_private_key {
        let sk = seed_to_private(my_private_key);
        let pk = csidh_rust::CSIDHPublicKey::from_bytes(peer_public_key.as_slice_less_safe());

        out[..64].copy_from_slice(&csidh_rust::agreement(&pk, &sk)[..]);
        Ok(())
    } else {
        Err(error::Unspecified)
    }
}
