use crate::{
    auth,
    serialization::{parse, Encode, Parse},
};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct EndpointRequest(pub(crate) auth::Signed<auth::Message>);

impl EndpointRequest {
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeRequest> {
        let input = parse::Input::new(data);
        let (_, inner) = auth::Signed::<auth::Message>::parse(input)
            .map_err(|e| DecodeRequest(e.to_string()))?;
        Ok(Self(inner))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("error decoding: {0}")]
pub struct DecodeRequest(pub(super) String);
