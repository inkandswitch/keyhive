use keyhive_core::crypto::verifiable::Verifiable;

use crate::{Signer, TaskContext};

use super::{
    audience::Audience,
    message::{Message, MessageValidationError},
    offset_seconds::OffsetSeconds,
    signed::Signed,
    unix_timestamp::UnixTimestamp,
};
use std::{collections::HashMap, future::Future, time::Duration};

pub struct Manager {
    /// Time offsets for each audience
    pub offsets: HashMap<Audience, OffsetSeconds>,
    signer: Signer,
}

impl Manager {
    pub(crate) fn new(signer: Signer) -> Self {
        Manager {
            offsets: HashMap::new(),
            signer,
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
    ) -> impl Future<Output = Signed<Message>> + 'static {
        let signer = self.signer.clone();
        let now_for_aud = self.now_for_audience(now, audience);
        async move {
            Signed::try_sign(
                signer,
                Message {
                    audience,
                    content,
                    expires_at: now_for_aud + Duration::from_secs(30),
                },
            )
            .await
            .expect("this never fails")
        }
    }

    pub(crate) fn receive_raw(
        &self,
        now: UnixTimestamp,
        signed: super::signed::Signed<super::message::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<super::Authenticated<Vec<u8>>, ReceiveMessageError> {
        signed
            .verify()
            .map_err(|e| ReceiveMessageError::ValidationFailed {
                reason: format!("invalid signature: {}", e),
            })?;

        let message = signed.payload;
        let verifier = signed.verifier;

        if let Some(receive_audience) = receive_audience {
            if let Ok(()) = message.validate(now, receive_audience) {
                return Ok(super::Authenticated {
                    from: verifier,
                    content: message.content,
                });
            }
        }

        message
            .validate(now, (&self.signer.verifying_key()).into())
            .map_err(|e| match e {
                MessageValidationError::Expired { .. } => ReceiveMessageError::Expired,
                MessageValidationError::SubjectMismatch => ReceiveMessageError::ValidationFailed {
                    reason: "invalid audience".to_string(),
                },
            })?;

        Ok(super::Authenticated {
            from: verifier,
            content: message.content,
        })
    }

    pub(crate) fn receive<T: for<'a> crate::serialization::Parse<'a>>(
        &self,
        now: UnixTimestamp,
        signed_message: super::signed::Signed<super::message::Message>,
        receive_audience: Option<Audience>,
    ) -> Result<super::Authenticated<T>, ReceiveMessageError> {
        let super::Authenticated {
            content,
            from: verifier,
        } = self.receive_raw(now, signed_message, receive_audience)?;

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
