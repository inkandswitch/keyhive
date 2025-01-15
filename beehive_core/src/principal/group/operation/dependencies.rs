use super::{delegation::Delegation, revocation::Revocation};
use crate::{
    content::reference::ContentRef, crypto::signed::Signed, principal::document::id::DocumentId,
};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependencies<'a, T: ContentRef> {
    pub delegations: Vec<Rc<Signed<Delegation<T>>>>,
    pub revocations: Vec<Rc<Signed<Revocation<T>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
