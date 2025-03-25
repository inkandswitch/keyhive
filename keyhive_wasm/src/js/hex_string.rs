#[derive(Debug, Clone)]
pub(crate) struct HexString(pub(crate) String);

impl HexString {
    #[allow(dead_code)]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes.iter().map(|b| format!("{:02x}", b)).collect())
    }

    #[allow(dead_code)]
    pub fn to_vec(&self) -> Result<Vec<u8>, String> {
        (0..self.0.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&self.0[i..i + 2], 16)
                    .map_err(|_| "Invalid hex character".to_string())
            })
            .collect::<Result<Vec<u8>, _>>()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
