use super::base64::Base64;
use derive_more::{From, Into};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use wasm_bindgen::prelude::*;
use wasm_refgen::wasm_refgen;

#[wasm_bindgen(js_name = ChangeId)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Into, From)]
pub struct JsChangeId(pub(crate) Vec<u8>);

#[wasm_refgen(js_ref = JsChangeIdRef)]
#[wasm_bindgen(js_class = ChangeId)]
impl JsChangeId {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub(crate) fn to_base64(&self) -> Base64 {
        Base64::from_vec(self.0.clone())
    }

    #[allow(dead_code)]
    pub(crate) fn from_base64(b64: Base64) -> Result<Self, base64_simd::Error> {
        Ok(Self(b64.into_vec()?))
    }
}

/// `bijou32(len) ‖ bytes`: a length prefix makes the variable-length id
/// self-delimiting, so a set of them packs back to back in a retention
/// watermark.
impl Encode for JsChangeId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        u32::try_from(self.0.len())
            .expect("a change id is shorter than 4 GiB")
            .encode_into(out);
        out.extend_from_slice(&self.0);
    }
}

impl Decode for JsChangeId {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for JsChangeId {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (len, rest) = u32::decode_next(bytes)?;
        let len =
            usize::try_from(len).map_err(|_| DecodeError::InvalidField("change id length"))?;
        let (id, rest) = rest
            .split_at_checked(len)
            .ok_or(DecodeError::UnexpectedEnd)?;
        Ok((JsChangeId(id.to_vec()), rest))
    }
}
