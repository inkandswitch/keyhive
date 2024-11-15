use std::str::FromStr;

use crate::{leb128, parse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct BlobMeta {
    hash: BlobHash,
    size_bytes: u64,
}

impl BlobMeta {
    pub(crate) fn new(contents: &[u8]) -> Self {
        let hash = BlobHash::hash_of(contents);
        let size_bytes = contents.len() as u64;
        Self { hash, size_bytes }
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, BlobMeta), parse::ParseError> {
        input.with_context("BlobMeta", |input| {
            let (input, hash) = BlobHash::parse(input)?;
            let (input, size_bytes) = leb128::parse(input)?;
            Ok((input, BlobMeta { hash, size_bytes }))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        self.hash.encode(buf);
        leb128::encode_uleb128(buf, self.size_bytes);
    }

    pub fn hash(&self) -> BlobHash {
        self.hash
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct BlobHash([u8; 32]);

impl std::fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlobHash({})", crate::hex::encode(&self.0))
    }
}

impl BlobHash {
    pub(crate) fn hash_of(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, BlobHash), parse::ParseError> {
        input.with_context("BlobHash", |input| {
            let (input, hash_bytes) = parse::arr::<32>(input)?;
            Ok((input, BlobHash::from(hash_bytes)))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl From<[u8; 32]> for BlobHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::hex::encode(&self.0).fmt(f)
    }
}

impl FromStr for BlobHash {
    type Err = error::InvalidBlobHash;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = crate::hex::decode(s).map_err(error::InvalidBlobHash::InvalidHex)?;
        if bytes.len() != 32 {
            return Err(error::InvalidBlobHash::InvalidLength);
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes);
        Ok(BlobHash(hash))
    }
}

mod error {
    use crate::parse;

    pub enum InvalidBlobHash {
        NotEnoughInput,
        InvalidHex(crate::hex::FromHexError),
        InvalidLength,
    }

    impl From<parse::NotEnoughInput> for InvalidBlobHash {
        fn from(_value: parse::NotEnoughInput) -> Self {
            Self::NotEnoughInput
        }
    }

    impl std::fmt::Display for InvalidBlobHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnoughInput => write!(f, "Not enough input"),
                Self::InvalidHex(err) => write!(f, "Invalid hex: {}", err),
                Self::InvalidLength => write!(f, "Invalid length"),
            }
        }
    }

    impl std::fmt::Debug for InvalidBlobHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidBlobHash {}

    pub enum InvalidBlobMeta {
        NotEnoughInput,
        InvalidBlobHash(InvalidBlobHash),
    }

    impl From<parse::NotEnoughInput> for InvalidBlobMeta {
        fn from(_value: parse::NotEnoughInput) -> Self {
            Self::NotEnoughInput
        }
    }

    impl From<InvalidBlobHash> for InvalidBlobMeta {
        fn from(value: InvalidBlobHash) -> Self {
            Self::InvalidBlobHash(value)
        }
    }

    impl std::fmt::Display for InvalidBlobMeta {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnoughInput => write!(f, "Not enough input"),
                Self::InvalidBlobHash(e) => write!(f, "Invalid blob hash: {}", e),
            }
        }
    }

    impl std::fmt::Debug for InvalidBlobMeta {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidBlobMeta {}
}
