//! Serializable representation of an [`Active`][super::Active] agent.

use crate::{
    crypto::share_key::{ShareKey, ShareSecretKey},
    principal::individual::Individual,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct ActiveArchive {
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,
}

impl Debug for ActiveArchive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // NOTE this pattern ensures that all fields are used
        let Self {
            prekey_pairs,
            individual,
        } = self;
        f.debug_struct("ActiveArchive")
            .field("prekey_pairs", &prekey_pairs.keys())
            .field("individual", &individual)
            .finish()
    }
}

impl Hash for ActiveArchive {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE this pattern ensures that all fields are used
        let Self {
            prekey_pairs,
            individual,
        } = self;
        prekey_pairs.keys().collect::<Vec<_>>().hash(state);
        individual.hash(state);
    }
}

impl PartialEq for ActiveArchive {
    fn eq(&self, other: &Self) -> bool {
        // NOTE this pattern ensures that all fields are used
        let Self {
            prekey_pairs,
            individual,
        } = self;
        *prekey_pairs == other.prekey_pairs && *individual == other.individual
    }
}

impl Eq for ActiveArchive {}
