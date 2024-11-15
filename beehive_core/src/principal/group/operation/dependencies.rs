use super::{delegation::Delegation, revocation::Revocation};
use crate::{
    content::reference::ContentRef,
    crypto::signed::Signed,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::id::DocumentId,
};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependencies<'a, T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub delegations: Vec<Rc<Signed<Delegation<T, L>>>>,
    pub revocations: Vec<Rc<Signed<Revocation<T, L>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
