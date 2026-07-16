use zeroize::Zeroize;

pub fn clear_secret(data: &mut Vec<u8>) {
    data.zeroize();
}
