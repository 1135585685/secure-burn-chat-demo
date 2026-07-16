pub mod cipher;
pub mod identity;
pub mod key_exchange;
pub mod memory;
pub mod ratchet;
pub mod secure_delete;
pub mod session;

#[no_mangle]
pub extern "C" fn crypto_core_version() -> u32 {
    20
}
