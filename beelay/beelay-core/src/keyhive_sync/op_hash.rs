use std::hash::{Hash, Hasher};

use keyhive_core::{crypto::digest::Digest, event::StaticEvent};

use crate::{
    parse::{self, Parse},
    riblt,
    serialization::{hex, Encode},
    CommitHash,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Hash, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct OpHash(pub(crate) [u8; 32]);

impl std::fmt::Debug for OpHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("OpHash")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

impl From<OpHash> for Digest<StaticEvent<CommitHash>> {
    fn from(hash: OpHash) -> Self {
        Self::from(hash.0)
    }
}

impl From<Digest<StaticEvent<CommitHash>>> for OpHash {
    fn from(digest: Digest<StaticEvent<CommitHash>>) -> Self {
        Self(*digest.raw.as_bytes())
    }
}

impl Encode for OpHash {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Parse<'_> for OpHash {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, hash) = parse::arr::<32>(input)?;
        Ok((input, Self(hash)))
    }
}

impl riblt::Symbol for OpHash {
    fn zero() -> Self {
        Self([0; 32])
    }

    fn xor(&self, other: &Self) -> Self {
        Self(std::array::from_fn(|i| self.0[i] ^ other.0[i]))
    }

    fn hash(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}
