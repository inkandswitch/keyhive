//! Serializable representation of an [`Active`][super::Active] individual.

use crate::principal::individual::IndividualState;
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use std::{
    collections::BTreeMap,
    fmt,
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};

#[derive(Clone)]
pub struct ActiveArchive {
    pub(crate) key_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`IndividualState`] representation (how others see it).
    pub(crate) individual: IndividualState,
}

impl Debug for ActiveArchive {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        f.debug_struct("ActiveArchive")
            .field("key_pairs", &key_pairs.keys())
            .field("individual", &individual)
            .finish()
    }
}

impl Hash for ActiveArchive {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        key_pairs.keys().collect::<Vec<_>>().hash(state);
        individual.hash(state);
    }
}

impl PartialEq for ActiveArchive {
    fn eq(&self, other: &Self) -> bool {
        // NOTE this pattern ensures that all fields are used
        let Self {
            key_pairs,
            individual,
        } = self;
        *key_pairs == other.key_pairs && *individual == other.individual
    }
}

impl Eq for ActiveArchive {}

/// `key_pairs ‖ individual`, the key pairs as a count and then ascending by
/// key. Decoding refuses a secret that is not its key's, as importing them
/// does.
impl Encode for ActiveArchive {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.key_pairs.encode_into(out);
        self.individual.encode_into(out);
    }
}

impl Decode for ActiveArchive {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for ActiveArchive {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (key_pairs, rest) = BTreeMap::<ShareKey, ShareSecretKey>::decode_next(bytes)?;
        if key_pairs.iter().any(|(pk, sk)| sk.share_key() != *pk) {
            return Err(DecodeError::InvalidField("key_pairs"));
        }
        let (individual, rest) = IndividualState::decode_next(rest)?;
        Ok((
            ActiveArchive {
                key_pairs,
                individual,
            },
            rest,
        ))
    }
}
