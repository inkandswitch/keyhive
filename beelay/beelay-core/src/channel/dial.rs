use ed25519_dalek::VerifyingKey;
use x25519_dalek::PublicKey;

#[derive(Debug, Clone)]
pub struct Dial {
    pub to: VerifyingKey,
    pub introduction_public_key: PublicKey,
}

impl From<Dial> for Vec<u8> {
    fn from(dial: Dial) -> Vec<u8> {
        let mut v = b"beelay:chan:dial:".to_vec();
        v.extend(dial.to.to_bytes());
        v.extend(b":");
        v.extend(dial.introduction_public_key.to_bytes());
        v
    }
}
