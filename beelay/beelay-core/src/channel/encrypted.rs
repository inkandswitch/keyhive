#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    pub ciphertext: Vec<u8>,
    pub seq_id: u64,
}
