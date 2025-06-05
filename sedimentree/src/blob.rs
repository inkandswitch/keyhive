use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct BlobMeta {
    digest: Digest,
    size_bytes: u64,
}

impl BlobMeta {
    pub fn new(contents: &[u8]) -> Self {
        let digest = Digest::new(contents);
        let size_bytes = contents.len() as u64;
        Self { digest, size_bytes }
    }

    pub fn from_digest_size(digest: Digest, size_bytes: u64) -> Self {
        BlobMeta { digest, size_bytes }
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Digest([u8; 32]);

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest({})", hex::encode(self.0))
    }
}

impl Digest {
    pub fn new(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl FromStr for Digest {
    type Err = error::InvalidDigest;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(error::InvalidDigest::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(error::InvalidDigest::InvalidLength);
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes);
        Ok(Digest(hash))
    }
}

mod error {

    pub enum InvalidDigest {
        NotEnoughInput,
        InvalidHex(hex::FromHexError),
        InvalidLength,
    }

    impl std::fmt::Display for InvalidDigest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnoughInput => write!(f, "Not enough input"),
                Self::InvalidHex(err) => write!(f, "Invalid hex: {}", err),
                Self::InvalidLength => write!(f, "Invalid length"),
            }
        }
    }

    impl std::fmt::Debug for InvalidDigest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidDigest {}
}
