use crate::agreement;
use crate::ec;
use crate::error;
use crate::rand;

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
    _rng: &rand::SecureRandom, out: &mut [u8],
) -> Result<(), error::Unspecified> {
    let sk = csidh_rust::CSIDHPrivateKey::generate();
    out[..csidh_rust::PRIVATE_KEY_LEN].copy_from_slice(sk.as_slice());
    Ok(())
}

fn seed_to_private(seed: &ec::Seed) -> csidh_rust::CSIDHPrivateKey {
    csidh_rust::CSIDHPrivateKey::from_bytes(seed.bytes_less_safe())
}


fn csidh_public_from_private(
    public_out: &mut [u8], private_key: &ec::Seed,
) -> Result<(), error::Unspecified> {
    let sk = seed_to_private(private_key);
    let pk = csidh_rust::CSIDHPublicKey::from_private(&sk);
    public_out[..csidh_rust::PUBLIC_KEY_LEN].copy_from_slice(pk.as_slice());
    Ok(())
}


pub static CSIDH: agreement::Algorithm = agreement::Algorithm {
    curve: &CURVE_CSIDH,
    ecdh: csidh_ecdh,
};



fn csidh_ecdh(
    out: &mut [u8], my_private_key: &ec::Seed, peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    let sk = seed_to_private(my_private_key);
    let pk = csidh_rust::CSIDHPublicKey::from_bytes(peer_public_key.as_slice_less_safe());

    out[..64].copy_from_slice(&csidh_rust::agreement(&pk, &sk)[..]);
    Ok(())
}
