use dupe::Dupe;
pub use error::InvalidCommitHash;

use crate::serialization::{hex, parse, Encode, Parse};

#[derive(
    Clone, Copy, Eq, Hash, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct CommitHash([u8; 32]);

impl Dupe for CommitHash {
    fn dupe(&self) -> Self {
        CommitHash(self.0)
    }
}

impl Encode for CommitHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for CommitHash {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("CommitHash", |input| {
            let (input, hash_bytes) = parse::arr::<32>(input)?;
            Ok((input, CommitHash::from(hash_bytes)))
        })
    }
}

impl CommitHash {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, CommitHash), parse::ParseError> {
        input.parse_in_ctx("CommitHash", |input| {
            let (input, hash_bytes) = parse::arr::<32>(input)?;
            Ok((input, CommitHash::from(hash_bytes)))
        })
    }
}

impl std::fmt::Display for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl std::fmt::Debug for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<[u8; 32]> for CommitHash {
    fn from(value: [u8; 32]) -> Self {
        CommitHash(value)
    }
}

impl<'a> From<&'a [u8; 32]> for CommitHash {
    fn from(value: &'a [u8; 32]) -> Self {
        CommitHash(*value)
    }
}

impl std::str::FromStr for CommitHash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(&bytes);
            Ok(CommitHash(id))
        } else {
            Err(hex::FromHexError::InvalidStringLength)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for CommitHash {
    type Error = error::InvalidCommitHash;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(value);
            Ok(CommitHash(id))
        } else {
            Err(error::InvalidCommitHash(value.len()))
        }
    }
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    #[error("invalid length {0} for commit hash, expected 32")]
    pub struct InvalidCommitHash(pub(super) usize);
}
