use crate::{
    auth,
    serialization::{parse, Encode, Parse},
};

// A wrapper around Envelope to avoid exposing the details of that enum to the public API.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct EndpointResponse(pub(crate) auth::signed::Signed<auth::message::Message>);

impl EndpointResponse {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeResponse> {
        let input = parse::Input::new(data);
        // let (_, inner) = Envelope::parse(input).map_err(|e| DecodeResponse(e.to_string()))?;
        let (_, inner) = auth::signed::Signed::<auth::message::Message>::parse(input)
            .map_err(|e| DecodeResponse(e.to_string()))?;
        Ok(Self(inner))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("error decoding: {0}")]
pub struct DecodeResponse(pub(super) String);
