use ed25519_dalek::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct IdentityKey {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Drop for IdentityKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

pub fn generate_identity() -> IdentityKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing = SigningKey::from_bytes(&secret);
    secret.zeroize();
    IdentityKey {
        private_key: signing.to_bytes().to_vec(),
        public_key: signing.verifying_key().to_bytes().to_vec(),
    }
}
