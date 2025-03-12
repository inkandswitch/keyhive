use crate::{
    auth,
    serialization::{parse, Encode, Parse},
};

// A wrapper around InnerRpcResponse to avoid exposing the details of that enum to the public API.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct RpcResponse(pub(crate) InnerRpcResponse);

impl RpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeResponse> {
        let input = parse::Input::new(data);
        let (_, inner) =
            InnerRpcResponse::parse(input).map_err(|e| DecodeResponse(e.to_string()))?;
        Ok(Self(inner))
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) enum InnerRpcResponse {
    // The incoming message failed authentication so we should send back an auth failed message
    AuthFailed,
    /// The signed response to an outgoing request
    Response(Box<auth::signed::Signed<auth::message::Message>>),
}

impl<'a> Parse<'a> for InnerRpcResponse {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("InnerRpcResponse", |input| {
            let (input, tag) = parse::u8(input)?;
            match tag {
                0 => Ok((input, InnerRpcResponse::AuthFailed)),
                1 => {
                    let (input, payload) =
                        auth::Signed::<auth::Message>::parse_in_ctx("payload", input)?;
                    Ok((input, InnerRpcResponse::Response(Box::new(payload))))
                }
                other => Err(input.error(format!("unknown response tag: {}", other))),
            }
        })
    }
}

impl Encode for InnerRpcResponse {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            InnerRpcResponse::AuthFailed => {
                out.push(0);
            }
            InnerRpcResponse::Response(msg) => {
                out.push(1);
                msg.encode_into(out);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("error decoding: {0}")]
pub struct DecodeResponse(pub(super) String);
