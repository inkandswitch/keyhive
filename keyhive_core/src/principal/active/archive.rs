//! Serializable representation of an [`Active`][super::Active] agent.

use crate::{
    crypto::share_key::{ShareKey, ShareSecretKey},
    principal::individual::Individual,
};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug, Hash, PartialEq, Eq)]
pub struct ActiveArchive {
    #[derivative(
        Debug(format_with = "crate::util::debug::prekey_fmt"),
        Hash(hash_with = "crate::util::hasher::keys"),
        PartialEq(compare_with = "crate::util::partial_eq::prekey_partial_eq")
    )]
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,
}
