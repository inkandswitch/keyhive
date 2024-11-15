use super::{node_id::NodeId, offset_seconds::OffsetSeconds, unix_timestamp::UnixTimestamp};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    pub expires_at: UnixTimestamp,
    pub audience: NodeId,
    pub content: Vec<u8>,
}

impl Message {
    pub fn new(offset: OffsetSeconds, audience: NodeId, content: Vec<u8>) -> Self {
        Self {
            expires_at: UnixTimestamp::now_with_offset(offset),
            audience,
            content,
        }
    }

    pub fn validate(&self, expected_audience: NodeId) -> Result<(), MessageValidationError> {
        if self.is_expired() {
            return Err(MessageValidationError::Expired {
                now: UnixTimestamp::now(),
            });
        }

        if !self.has_correct_audience(expected_audience) {
            return Err(MessageValidationError::SubjectMismatch);
        }

        Ok(())
    }

    pub fn has_correct_audience(&self, expected_audience: NodeId) -> bool {
        self.audience == expected_audience
    }

    pub fn is_expired(&self) -> bool {
        UnixTimestamp::now() > self.expires_at
    }
}

impl From<Message> for Vec<u8> {
    fn from(message: Message) -> Vec<u8> {
        let mut buf = b"/beelay/msg/".to_vec();
        buf.extend_from_slice(&message.expires_at.0.to_be_bytes());
        buf.extend_from_slice(&message.audience.0);
        buf.extend_from_slice(message.content.as_slice());
        buf
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = MessageDecodeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let buf = bytes.as_slice();

        if buf[..12] != *b"/beelay/msg/" {
            return Err(MessageDecodeError::InvalidHeader);
        }

        let expires_at = u64::from_be_bytes(
            buf[12..20]
                .try_into()
                .or(Err(MessageDecodeError::CannotDecodeExpiry))?,
        )
        .into();

        let audience_bytes: [u8; 32] = buf[20..52]
            .try_into()
            .or(Err(MessageDecodeError::CannotDecodeAudience))?;

        Ok(Message {
            expires_at,
            audience: audience_bytes.into(),
            content: buf[52..].to_vec(),
        })
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MessageValidationError {
    #[error("Message has expired")]
    Expired { now: UnixTimestamp },

    #[error("Message has incorrect audience")]
    SubjectMismatch,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MessageDecodeError {
    #[error("Invalid message header")]
    InvalidHeader,

    #[error("Cannot decode expiry")]
    CannotDecodeExpiry,

    #[error("Cannot decode audience")]
    CannotDecodeAudience,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let message = Message::new(
            OffsetSeconds(123),
            "sync.example.com".into(),
            b"hello".to_vec(),
        );
        let encoded: Vec<u8> = message.clone().into();
        let decoded = encoded.try_into().unwrap();
        assert_eq!(message, decoded);
    }
}
