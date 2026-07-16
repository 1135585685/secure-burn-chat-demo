use zeroize::Zeroize;

pub fn destroy_key(key: &mut [u8; 32]) {
    key.zeroize();
}
