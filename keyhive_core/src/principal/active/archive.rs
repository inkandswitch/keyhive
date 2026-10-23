//! Serializable representation of an [`Active`][super::Active] individual.

use crate::principal::individual::IndividualState;
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};

#[derive(Clone, Serialize, Deserialize)]
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
