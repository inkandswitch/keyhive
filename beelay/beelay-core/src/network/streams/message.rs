use crate::{
    parse::{self, Parse},
    serialization::Encode,
    Request, Response,
};

use super::{connection::ConnRequestId, handshake::HandshakeFailure};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum StreamMessage {
    Hello,
    HelloBack,
    HandshakeFailure(HandshakeFailure),
    Request {
        id: ConnRequestId,
        req: Box<Request>,
    },
    Response {
        id: ConnRequestId,
        resp: Box<Response>,
    },
    Error(String),
}

enum MessageType {
    Hello,
    HelloBack,
    HandshakeFailure,
    Request,
    Response,
    Error,
}

impl TryFrom<u8> for MessageType {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, u8> {
        match value {
            0 => Ok(MessageType::Hello),
            1 => Ok(MessageType::HelloBack),
            2 => Ok(MessageType::HandshakeFailure),
            3 => Ok(MessageType::Request),
            4 => Ok(MessageType::Response),
            5 => Ok(MessageType::Error),
            other => Err(other),
        }
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Hello => 0,
            MessageType::HelloBack => 1,
            MessageType::HandshakeFailure => 2,
            MessageType::Request => 3,
            MessageType::Response => 4,
            MessageType::Error => 5,
        }
    }
}

impl Encode for StreamMessage {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            StreamMessage::Hello => {
                out.push(MessageType::Hello.into());
            }
            StreamMessage::HelloBack => {
                out.push(MessageType::HelloBack.into());
            }
            StreamMessage::HandshakeFailure(handshake_failure) => {
                out.push(MessageType::HandshakeFailure.into());
                handshake_failure.encode_into(out);
            }
            StreamMessage::Request { id, req } => {
                out.push(MessageType::Request.into());
                id.encode_into(out);
                req.encode_into(out);
            }
            StreamMessage::Response { id, resp } => {
                out.push(MessageType::Response.into());
                id.encode_into(out);
                resp.encode_into(out);
            }
            StreamMessage::Error(error) => {
                out.push(MessageType::Error.into());
                error.encode_into(out);
            }
        }
    }
}

impl<'a> Parse<'a> for StreamMessage {
    fn parse(
        input: crate::parse::Input<'a>,
    ) -> Result<(crate::parse::Input<'a>, Self), crate::parse::ParseError> {
        input.parse_in_ctx("Message", |input| {
            let (input, tag) = input.parse_in_ctx("message type", |input| parse::u8(input))?;
            let message_type = MessageType::try_from(tag)
                .map_err(|e| input.error(format!("unknown message type tag: {}", e)))?;
            match message_type {
                MessageType::Hello => {
                    input.parse_in_ctx("Hello", |input| Ok((input, StreamMessage::Hello)))
                }
                MessageType::HelloBack => Ok((input, StreamMessage::HelloBack)),
                MessageType::HandshakeFailure => input.parse_in_ctx("HandshakeFailure", |input| {
                    let (input, failure) = HandshakeFailure::parse(input)?;
                    Ok((input, StreamMessage::HandshakeFailure(failure)))
                }),
                MessageType::Request => input.parse_in_ctx("Request", |input| {
                    let (input, id) = input.parse_in_ctx("request id", ConnRequestId::parse)?;
                    let (input, req) = input.parse_in_ctx("request", Request::parse)?;
                    Ok((
                        input,
                        StreamMessage::Request {
                            id,
                            req: Box::new(req),
                        },
                    ))
                }),
                MessageType::Response => input.parse_in_ctx("Response", |input| {
                    let (input, id) = input.parse_in_ctx("response id", ConnRequestId::parse)?;
                    let (input, resp) = input.parse_in_ctx("response", Response::parse)?;
                    Ok((
                        input,
                        StreamMessage::Response {
                            id,
                            resp: Box::new(resp),
                        },
                    ))
                }),
                MessageType::Error => input.parse_in_ctx("Error", |input| {
                    let (input, error) = parse::str(input)?;
                    Ok((input, StreamMessage::Error(error.to_string())))
                }),
            }
        })
    }
}
