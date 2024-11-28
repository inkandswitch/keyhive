use super::{mac::Mac, secret::Secret};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    pub sender: ed25519_dalek::VerifyingKey,
    pub content: Vec<u8>,
    pub mac: Mac,
}

impl Message {
    pub fn new(sender: ed25519_dalek::VerifyingKey, secret: &Secret, content: Vec<u8>) -> Self {
        let mut buf = b"/beelay/message/".to_vec();
        buf.extend_from_slice(content.as_slice());

        Self {
            sender,
            mac: Mac(*blake3::keyed_hash(&secret.0, &buf).as_bytes()),
            content,
        }
    }

    pub fn is_valid(&self, secret: &[u8; 32]) -> bool {
        let mut buf = b"/beelay/message/".to_vec();
        buf.extend_from_slice(self.content.as_slice());
        self.mac == Mac(*blake3::keyed_hash(&secret, &buf).as_bytes())
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Vec<u8> {
        let mut buf = message.sender.to_bytes().to_vec();
        buf.extend_from_slice(&message.mac.to_bytes());
        buf.extend_from_slice(message.content.as_slice());
        buf
    }
}
