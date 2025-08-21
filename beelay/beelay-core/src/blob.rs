use std::str::FromStr;

use crate::serialization::{leb128, parse, Encode, Parse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Hash, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct BlobMeta {
    hash: BlobHash,
    size_bytes: u64,
}

impl From<BlobMeta> for sedimentree::BlobMeta {
    fn from(val: BlobMeta) -> Self {
        sedimentree::BlobMeta::from_digest_size(val.hash.into(), val.size_bytes)
    }
}
impl From<sedimentree::BlobMeta> for BlobMeta {
    fn from(value: sedimentree::BlobMeta) -> Self {
        Self {
            hash: value.digest().into(),
            size_bytes: value.size_bytes(),
        }
    }
}

impl Encode for BlobMeta {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.hash.encode_into(out);
        leb128::encode_uleb128(out, self.size_bytes);
    }
}

impl Parse<'_> for BlobMeta {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("BlobMeta", |input| {
            let (input, hash) = input.parse_in_ctx("hash", BlobHash::parse)?;
            let (input, size_bytes) = input.parse_in_ctx("size", leb128::parse)?;
            Ok((input, BlobMeta { hash, size_bytes }))
        })
    }
}

impl BlobMeta {
    pub(crate) fn new(contents: &[u8]) -> Self {
        let hash = BlobHash::hash_of(contents);
        let size_bytes = contents.len() as u64;
        Self { hash, size_bytes }
    }

    pub fn hash(&self) -> BlobHash {
        self.hash
    }
}

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, Hash, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct BlobHash([u8; 32]);

impl From<BlobHash> for sedimentree::Digest {
    fn from(val: BlobHash) -> Self {
        sedimentree::Digest::from_raw_bytes(val.0)
    }
}
impl From<sedimentree::Digest> for BlobHash {
    fn from(value: sedimentree::Digest) -> Self {
        BlobHash(*value.as_bytes())
    }
}

impl Encode for BlobHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for BlobHash {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, BlobHash), parse::ParseError> {
        input.parse_in_ctx("BlobHash", |input| {
            let (input, hash_bytes) = input.parse_in_ctx("hash", parse::arr::<32>)?;
            Ok((input, BlobHash::from(hash_bytes)))
        })
    }
}

impl std::fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BlobHash({})",
            crate::serialization::hex::encode(&self.0)
        )
    }
}

impl BlobHash {
    pub(crate) fn hash_of(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }
}

impl From<[u8; 32]> for BlobHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for BlobHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::serialization::hex::encode(&self.0).fmt(f)
    }
}

impl FromStr for BlobHash {
    type Err = error::InvalidBlobHash;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            crate::serialization::hex::decode(s).map_err(error::InvalidBlobHash::InvalidHex)?;
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
        InvalidHex(crate::serialization::hex::FromHexError),
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
}
