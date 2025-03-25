#[derive(Debug, Clone)]
pub(crate) struct Base64(pub(crate) String);

impl Base64 {
    #[allow(dead_code)]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(base64_simd::STANDARD.encode_to_string(bytes))
    }

    #[allow(dead_code)]
    pub fn into_vec(self) -> Result<Vec<u8>, base64_simd::Error> {
        base64_simd::STANDARD.decode_to_vec(self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
