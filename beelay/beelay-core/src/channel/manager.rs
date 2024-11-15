use super::{
    message::{Message, MessageValidationError},
    node_id::NodeId,
    offset_seconds::OffsetSeconds,
    signed::Signed,
    unix_timestamp::UnixTimestamp,
};
use std::{collections::HashMap, time::Duration};
use thiserror::Error;

pub struct Manager {
    /// Either exactly the verifying key,
    /// or the BLAKE3 digest of a hostname
    /// or other context-specific identifier
    pub id: NodeId,

    /// The EdDSA signing key
    pub signing_key: ed25519_dalek::SigningKey,

    /// Time offsets for each audience
    pub offsets: HashMap<NodeId, OffsetSeconds>,
}

impl Manager {
    pub fn new(signing_key: ed25519_dalek::SigningKey, id: Option<NodeId>) -> Self {
        Manager {
            id: id.unwrap_or_else(|| (&signing_key).into()),
            signing_key,
            offsets: HashMap::new(),
        }
    }

    pub fn update_offset(&mut self, from: NodeId, their_time: UnixTimestamp) {
        self.offsets.insert(from, UnixTimestamp::now() - their_time);
    }

    pub fn now_for_audience(&self, audience: NodeId) -> UnixTimestamp {
        UnixTimestamp::now() + self.offsets.get(&audience).map(|s| *s).unwrap_or_default()
    }

    pub fn send_message(
        &self,
        audience: NodeId,
        content: Vec<u8>,
        expires_in_seconds: Option<Duration>,
    ) -> Result<Signed<Message>, signature::Error> {
        let now = self.now_for_audience(audience);

        Signed::try_sign(
            Message {
                audience,
                content,
                expires_at: now + expires_in_seconds.unwrap_or_else(|| Duration::from_secs(30)),
            },
            &self.signing_key,
        )
    }

    pub fn receive_message(
        &self,
        signed_message: Signed<Message>,
    ) -> Result<Vec<u8>, ReceiveMessageError> {
        signed_message.verify()?;

        let message = signed_message.payload;

        if let Ok(()) = message.validate(self.id) {
            return Ok(message.content);
        }

        message.validate((&self.signing_key).into())?;
        Ok(message.content)
    }
}

#[derive(Debug, Error)]
pub enum ReceiveMessageError {
    #[error(transparent)]
    MessageError(#[from] MessageValidationError),

    #[error(transparent)]
    SignatureError(#[from] signature::Error),
}
