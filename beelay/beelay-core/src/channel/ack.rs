use x25519_dalek::PublicKey;

#[derive(Debug, Clone)]
pub struct Ack {
    pub you: PublicKey,
    pub me: PublicKey,
}

impl From<Ack> for Vec<u8> {
    fn from(ack: Ack) -> Vec<u8> {
        let mut buf = b"beelay:chan:ack:".to_vec();
        buf.extend(ack.you.to_bytes());
        buf.extend(ack.me.to_bytes());
        buf
    }
}
