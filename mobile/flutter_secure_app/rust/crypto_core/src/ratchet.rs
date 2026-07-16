use zeroize::Zeroize;

pub struct MessageKey {
    pub key: [u8; 32],
    pub index: u64,
}

impl Drop for MessageKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
