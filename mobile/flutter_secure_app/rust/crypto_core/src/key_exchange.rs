use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct EphemeralKeyPair {
    pub secret: EphemeralSecret,
    pub public: PublicKey,
}

pub fn generate_ephemeral_key() -> EphemeralKeyPair {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    EphemeralKeyPair { secret, public }
}

pub fn derive_shared_secret(secret: EphemeralSecret, peer_public: PublicKey) -> [u8; 32] {
    secret.diffie_hellman(&peer_public).to_bytes()
}
