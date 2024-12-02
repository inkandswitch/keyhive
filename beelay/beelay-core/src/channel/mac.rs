#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mac(pub(crate) [u8; 32]);

impl Mac {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<Mac> for [u8; 32] {
    fn from(mac: Mac) -> Self {
        mac.0
    }
}
