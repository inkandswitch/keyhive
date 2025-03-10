//! Archive of [`Keyhive`][crate::keyhive::Keyhive].

use crate::{
    content::reference::ContentRef,
    crypto::digest::Digest,
    principal::{
        active::archive::ActiveArchive,
        document::{archive::DocumentArchive, id::DocumentId},
        group::{id::GroupId, membership_operation::StaticMembershipOperation, GroupArchive},
        individual::{id::IndividualId, Individual},
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Serialized representation of [`Keyhive`][crate::keyhive::Keyhive].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archive<T: ContentRef> {
    pub(crate) active: ActiveArchive,
    pub(crate) topsorted_ops: Vec<(
        Digest<StaticMembershipOperation<T>>,
        StaticMembershipOperation<T>,
    )>,
    pub(crate) individuals: HashMap<IndividualId, Individual>,
    pub(crate) groups: HashMap<GroupId, GroupArchive<T>>,
    pub(crate) docs: HashMap<DocumentId, DocumentArchive<T>>,
}

impl<T: ContentRef> Archive<T> {
    /// Getter for the user that the [`Archive`] is for.
    pub fn id(&self) -> IndividualId {
        self.active.individual.id()
    }
}
