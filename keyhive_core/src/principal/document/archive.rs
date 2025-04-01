use crate::{
    cgka::archive::CgkaArchive, content::reference::ContentRef, principal::group::GroupArchive,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentArchive<T: ContentRef> {
    pub(crate) group: GroupArchive<T>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Option<CgkaArchive>,
}

impl<T: ContentRef> DocumentArchive<T> {
    pub fn group(&self) -> &GroupArchive<T> {
        &self.group
    }

    pub fn content_heads(&self) -> &HashSet<T> {
        &self.content_heads
    }

    pub fn content_state(&self) -> &HashSet<T> {
        &self.content_state
    }

    pub fn cgka(&self) -> Option<&CgkaArchive> {
        self.cgka.as_ref()
    }

    pub fn set_cgka(&mut self, cgka: CgkaArchive) {
        self.cgka = Some(cgka)
    }
}
