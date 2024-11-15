use ed25519_dalek::VerifyingKey;

use crate::{
    auth,
    serialization::{parse, Encode, Parse},
};

// This is a wrapper type which forms the public API for auth::sign::Signed<auth::message::Message>.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct SignedMessage(pub(crate) auth::signed::Signed<auth::message::Message>);

impl SignedMessage {
    pub fn decode(data: &[u8]) -> Result<Self, DecodeMessage> {
        let input = parse::Input::new(data);
        let (_input, result) = Parse::parse(input).map_err(|e| DecodeMessage(e.to_string()))?;
        Ok(result)
    }

    pub fn encode(&self) -> Vec<u8> {
        Encode::encode(self)
    }
}

impl Encode for SignedMessage {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.0.encode_into(out);
    }
}

impl<'a> Parse<'a> for SignedMessage {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        let (input, result) = auth::signed::Signed::<auth::message::Message>::parse(input)?;
        Ok((input, Self(result)))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("error decoding: {0}")]
pub struct DecodeMessage(pub(super) String);
