use super::{delegation::Delegation, revocation::Revocation};
use crate::{
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::id::DocumentId,
};
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::{collections::BTreeMap, hash::Hash, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependencies<
    'a,
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub delegations: Vec<Arc<Signed<Delegation<S, T, L>>>>,
    pub revocations: Vec<Arc<Signed<Revocation<S, T, L>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
