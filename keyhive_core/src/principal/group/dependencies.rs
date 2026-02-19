use super::{delegation::Delegation, revocation::Revocation};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    listener::membership::MembershipListener,
    principal::document::id::DocumentId,
};
use derive_where::derive_where;
use future_form::FutureForm;
use std::{collections::BTreeMap, sync::Arc};

#[derive_where(Debug, Clone, PartialEq, Eq, Hash; T)]
pub struct Dependencies<
    'a,
    K: FutureForm + ?Sized,
    S: AsyncSigner,
    T: ContentRef,
    L: MembershipListener<K, S, T>,
> {
    pub delegations: Vec<Arc<Signed<Delegation<K, S, T, L>>>>,
    pub revocations: Vec<Arc<Signed<Revocation<K, S, T, L>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
