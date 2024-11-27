use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Disconnect(pub VerifyingKey);

impl From<Disconnect> for Vec<u8> {
    fn from(disconnect: Disconnect) -> Vec<u8> {
        let mut v = b"beelay:chan:disconnect:".to_vec();
        v.extend(disconnect.0.to_bytes());
        v
    }
}
