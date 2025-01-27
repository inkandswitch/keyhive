use crate::serialization::{parse, Encode, Parse};

use super::{audience::Audience, offset_seconds::OffsetSeconds, unix_timestamp::UnixTimestamp};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct Message {
    pub expires_at: UnixTimestamp,
    pub audience: Audience,
    pub content: Vec<u8>,
}

impl<'a> Parse<'a> for Message {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("Message", |input| {
            let (input, header) = input.parse_in_ctx("header", parse::arr::<12>)?;
            if header != *b"/beelay/msg/" {
                return Err(input.error("Invalid message header"));
            }
            let (input, expires_at) = UnixTimestamp::parse_in_ctx("expires_at", input)?;
            let (input, audience) = Audience::parse_in_ctx("audience", input)?;
            let (input, content) = input.parse_in_ctx("content", parse::slice)?;
            Ok((
                input,
                Self {
                    expires_at,
                    audience,
                    content: content.to_vec(),
                },
            ))
        })
    }
}

impl Encode for Message {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"/beelay/msg/");
        self.expires_at.encode_into(out);
        self.audience.encode_into(out);
        self.content.encode_into(out);
    }
}

impl Message {
    pub fn new(offset: OffsetSeconds, audience: Audience, content: Vec<u8>) -> Self {
        Self {
            expires_at: UnixTimestamp::now_with_offset(offset),
            audience,
            content,
        }
    }

    pub fn validate(
        &self,
        now: UnixTimestamp,
        expected_audience: Audience,
    ) -> Result<(), MessageValidationError> {
        if self.is_expired(now) {
            return Err(MessageValidationError::Expired { now });
        }

        if !self.has_correct_audience(expected_audience) {
            return Err(MessageValidationError::SubjectMismatch);
        }

        Ok(())
    }

    pub fn has_correct_audience(&self, expected_audience: Audience) -> bool {
        self.audience == expected_audience
    }

    pub fn is_expired(&self, now: UnixTimestamp) -> bool {
        now > self.expires_at
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MessageValidationError {
    #[error("Message has expired")]
    Expired { now: UnixTimestamp },

    #[error("Message has incorrect audience")]
    SubjectMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let message = Message::new(
            OffsetSeconds(123),
            Audience::service_name("sync.example.com"),
            b"hello".to_vec(),
        );
        let mut encoded = Vec::new();
        message.encode_into(&mut encoded);
        let (_, decoded) =
            Message::parse(parse::Input::new(&encoded)).expect("message failed to parse");
        assert_eq!(message, decoded);
    }
}
