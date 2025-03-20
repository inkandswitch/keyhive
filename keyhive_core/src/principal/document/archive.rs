use crate::{cgka::Cgka, content::reference::ContentRef, principal::group::GroupArchive};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) group: GroupArchive<T>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Option<Cgka>,
}
