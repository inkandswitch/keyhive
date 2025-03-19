use crate::{
    cgka::Cgka,
    content::reference::ContentRef,
    crypto::share_key::ShareKey,
    principal::{group::GroupArchive, individual::id::IndividualId},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) group: GroupArchive<T>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Option<Cgka>,
}
