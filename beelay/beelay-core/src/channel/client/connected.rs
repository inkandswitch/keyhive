use super::super::{message::Message, secret::Secret};

pub struct Connected {
    pub sender: ed25519_dalek::VerifyingKey,
    pub secret: Secret,
}

impl Connected {
    pub fn message(&self, content: Vec<u8>) -> Message {
        Message::new(self.sender, &self.secret, content)
    }
}
