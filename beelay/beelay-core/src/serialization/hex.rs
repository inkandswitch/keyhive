pub(crate) fn encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

pub(crate) fn decode<S: AsRef<str>>(s: S) -> Result<Vec<u8>, FromHexError> {
    let s = s.as_ref();
    if s.len() % 2 != 0 {
        return Err(FromHexError::InvalidStringLength);
    }

    let s = s.as_bytes();

    s.chunks(2)
        .enumerate()
        .map(|(i, pair)| Ok(val(pair[0], 2 * i)? << 4 | val(pair[1], 2 * i + 1)?))
        .collect()
}

fn val(c: u8, idx: usize) -> Result<u8, FromHexError> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(FromHexError::InvalidHexCharacter(c as char, idx)),
    }
}

pub enum FromHexError {
    InvalidHexCharacter(char, usize),
    InvalidStringLength,
}

impl std::fmt::Debug for FromHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FromHexError::InvalidHexCharacter(c, idx) => {
                write!(f, "Invalid hex character '{}' at index {}", c, idx)
            }
            FromHexError::InvalidStringLength => {
                write!(f, "Invalid string length")
            }
        }
    }
}

impl std::fmt::Display for FromHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for FromHexError {}

#[cfg(test)]
mod tests {
    #[test]
    fn hex_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<Vec<u8>>()
            .for_each(|bytes| {
                let encoded = super::encode(bytes);
                let decoded = super::decode(encoded).unwrap();
                assert_eq!(bytes, &decoded);
            });
    }
}
