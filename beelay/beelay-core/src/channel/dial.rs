use ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dial {
    pub to: VerifyingKey,
    pub challenge: u128,
}

impl From<Dial> for Vec<u8> {
    fn from(dial: Dial) -> Vec<u8> {
        let mut v = b"beelay:chan:dial:".to_vec();
        v.extend(dial.to.to_bytes());
        v.extend(dial.challenge.to_be_bytes());
        v
    }
}
