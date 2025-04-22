use std::time::Duration;

use ed25519_dalek::VerifyingKey;

pub mod audience;
pub mod message;
pub(crate) use message::Message;
pub mod offset_seconds;
pub mod signed;
use message::MessageValidationError;
use offset_seconds::OffsetSeconds;
pub(crate) use signed::Signed;

use crate::{Audience, PeerId, UnixTimestamp};

#[derive(Debug)]
pub(crate) struct Authenticated<T> {
    pub(crate) from: VerifyingKey,
    pub(crate) content: T,
}

pub(crate) fn receive_raw(
    now: UnixTimestamp,
    signed: signed::Signed<message::Message>,
    receiver: &PeerId,
    receive_audience: Option<Audience>,
) -> Result<Authenticated<Vec<u8>>, ReceiveMessageError> {
    signed
        .verify()
        .map_err(|e| ReceiveMessageError::ValidationFailed {
            reason: format!("invalid signature: {}", e),
        })?;

    let message = signed.payload;
    let verifier = signed.verifier;

    if let Some(receive_audience) = receive_audience {
        if let Ok(()) = message.validate(now, receive_audience) {
            return Ok(Authenticated {
                from: verifier,
                content: message.content,
            });
        }
    }

    message
        .validate(now, Audience::peer(receiver))
        .map_err(|e| match e {
            MessageValidationError::Expired { .. } => ReceiveMessageError::Expired,
            MessageValidationError::SubjectMismatch => ReceiveMessageError::ValidationFailed {
                reason: "invalid audience".to_string(),
            },
        })?;

    Ok(Authenticated {
        from: verifier,
        content: message.content,
    })
}

pub(crate) fn receive<T: for<'a> crate::serialization::Parse<'a>>(
    now: UnixTimestamp,
    signed_message: signed::Signed<message::Message>,
    receiver: &PeerId,
    receive_audience: Option<Audience>,
) -> Result<Authenticated<T>, ReceiveMessageError> {
    let Authenticated {
        content,
        from: verifier,
    } = receive_raw(now, signed_message, receiver, receive_audience)?;

    let input = crate::parse::Input::new(&content);
    let (_, parsed) = T::parse(input).map_err(|e| {
        tracing::warn!(?e, "failed to parse message");
        ReceiveMessageError::InvalidPayload {
            reason: e,
            sender: Box::new(verifier.into()),
        }
    })?;

    Ok(Authenticated {
        from: verifier,
        content: parsed,
    })
}

pub(crate) fn send(
    now: UnixTimestamp,
    receiver_offset: OffsetSeconds,
    audience: Audience,
    content: Vec<u8>,
) -> Message {
    let now_for_receiver = now - receiver_offset;
    Message {
        audience,
        content,
        expires_at: now_for_receiver + Duration::from_secs(30),
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
