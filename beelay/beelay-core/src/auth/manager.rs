use super::{
    audience::Audience,
    message::{Message, MessageValidationError},
    offset_seconds::OffsetSeconds,
    signed::Signed,
    unix_timestamp::UnixTimestamp,
};
use std::{collections::HashMap, time::Duration};

pub struct Manager {
    /// Either exactly the verifying key,
    /// or the BLAKE3 digest of a hostname
    /// or other context-specific identifier
    pub id: Audience,

    /// The EdDSA signing key
    pub signing_key: ed25519_dalek::SigningKey,

    /// Time offsets for each audience
    pub offsets: HashMap<Audience, OffsetSeconds>,
}

impl Manager {
    pub(crate) fn new(signing_key: ed25519_dalek::SigningKey, id: Option<Audience>) -> Self {
        Manager {
            id: id.unwrap_or_else(|| (&signing_key).into()),
            signing_key,
            offsets: HashMap::new(),
        }
    }

    pub(crate) fn update_offset(
        &mut self,
        now: UnixTimestamp,
        from: Audience,
        their_time: UnixTimestamp,
    ) {
        self.offsets.insert(from, now - their_time);
    }

    pub(crate) fn now_for_audience(&self, now: UnixTimestamp, audience: Audience) -> UnixTimestamp {
        if let Some(offset) = self.offsets.get(&audience) {
            tracing::trace!(?offset, ?audience, ?now, "offset found");
            now - *offset
        } else {
            now
        }
    }

    pub(crate) fn send(
        &self,
        now: UnixTimestamp,
        audience: Audience,
        content: Vec<u8>,
    ) -> Signed<Message> {
        let now_for_aud = self.now_for_audience(now, audience);
        Signed::try_sign(
            Message {
                audience,
                content,
                expires_at: now_for_aud + Duration::from_secs(30),
            },
            &self.signing_key,
        )
        .expect("this never fails")
    }

    pub(crate) fn receive_raw(
        &self,
        now: UnixTimestamp,
        signed: super::signed::Signed<super::message::Message>,
    ) -> Result<super::Authenticated<Vec<u8>>, ReceiveMessageError> {
        signed
            .verify()
            .map_err(|e| ReceiveMessageError::ValidationFailed {
                reason: format!("invalid signature: {}", e),
            })?;

        let message = signed.payload;
        let verifier = signed.verifier;

        if let Ok(()) = message.validate(now, self.id) {
            Ok(super::Authenticated {
                from: verifier,
                content: message.content,
            })
        } else {
            message
                .validate(now, (&self.signing_key).into())
                .map_err(|e| match e {
                    MessageValidationError::Expired { .. } => ReceiveMessageError::Expired,
                    MessageValidationError::SubjectMismatch => {
                        ReceiveMessageError::ValidationFailed {
                            reason: "invalid audience".to_string(),
                        }
                    }
                })?;

            Ok(super::Authenticated {
                from: verifier,
                content: message.content,
            })
        }
    }

    pub(crate) fn receive<T: for<'a> crate::deser::Parse<'a>>(
        &self,
        now: UnixTimestamp,
        signed_message: super::signed::Signed<super::message::Message>,
    ) -> Result<super::Authenticated<T>, ReceiveMessageError> {
        let super::Authenticated {
            content,
            from: verifier,
        } = self.receive_raw(now, signed_message)?;

        let input = crate::parse::Input::new(&content);
        let (_, parsed) = T::parse(input).map_err(|e| {
            tracing::warn!(?e, "failed to parse message");
            ReceiveMessageError::InvalidPayload {
                reason: e,
                sender: Box::new(verifier.into()),
            }
        })?;

        Ok(super::Authenticated {
            from: verifier,
            content: parsed,
        })
    }
}

#[derive(Debug)]
pub(crate) enum ReceiveMessageError {
    InvalidPayload {
        reason: crate::parse::ParseError,
        sender: Box<crate::PeerId>,
    },
    ValidationFailed {
        reason: String,
    },
    Expired,
}

impl std::fmt::Display for ReceiveMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPayload { reason, sender } => {
                write!(f, "invalid payload ({}) from {}", reason, sender)
            }
            Self::ValidationFailed { reason } => write!(f, "validation failed: {}", reason),
            Self::Expired => write!(f, "message expired"),
        }
    }
}

impl std::error::Error for ReceiveMessageError {}
