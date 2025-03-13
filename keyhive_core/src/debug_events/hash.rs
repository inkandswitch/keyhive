use std::fmt;

/// A wrapper around a byte array representing a hash
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hash {
    Hash(Vec<u8>),
    Nickname { original: Vec<u8>, nickname: String },
}

impl Hash {
    /// Create a new Hash from bytes
    pub fn new(bytes: &[u8], nicknames: &super::Nicknames) -> Self {
        if let Some(nickname) = nicknames.names.get(bytes) {
            Self::Nickname {
                original: bytes.to_vec(),
                nickname: nickname.clone(),
            }
        } else {
            Self::Hash(bytes.to_vec())
        }
    }

    /// Generate a shortened hex representation (first 6 and last 4 characters)
    pub fn short_hex(&self) -> String {
        match self {
            Self::Nickname { nickname, .. } => nickname.clone(),
            Self::Hash(hash) => {
                let mut hex = String::with_capacity(hash.len() * 2);
                for byte in hash {
                    hex.push_str(&format!("{:02x}", byte));
                }

                if hex.len() > 10 {
                    format!("{}...{}", &hex[0..6], &hex[hex.len() - 4..])
                } else {
                    hex
                }
            }
        }
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_hex())
    }
}
