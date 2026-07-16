use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Created,
    Active,
    Destroying,
    Destroyed,
}

pub struct SecureSession {
    pub session_id: String,
    pub key: [u8; 32],
    pub state: SessionState,
}

impl SecureSession {
    pub fn destroy(&mut self) {
        self.state = SessionState::Destroying;
        self.key.zeroize();
        self.state = SessionState::Destroyed;
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
