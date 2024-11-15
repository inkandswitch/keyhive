use crate::{
    content::reference::ContentRef,
    crypto::digest::Digest,
    principal::{
        active::Active,
        document::{id::DocumentId, DocumentArchive},
        group::{id::GroupId, operation::StaticOperation, GroupArchive},
        individual::{id::IndividualId, Individual},
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Archive<T: ContentRef> {
    pub(crate) active: Active,
    pub(crate) topsorted_ops: Vec<(Digest<StaticOperation<T>>, StaticOperation<T>)>,
    pub(crate) individuals: HashMap<IndividualId, Individual>,
    pub(crate) groups: HashMap<GroupId, GroupArchive<T>>,
    pub(crate) docs: HashMap<DocumentId, DocumentArchive<T>>,
}
