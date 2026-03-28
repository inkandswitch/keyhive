use super::{delegation::Delegation, revocation::Revocation};
use crate::store::secret_key::SecretKeyStore;
use crate::{
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::id::DocumentId,
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use std::{collections::BTreeMap, hash::Hash, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependencies<
    'a,
    F: FutureForm,
    S: AsyncSigner<F>,
    K: SecretKeyStore<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, K, T> = NoListener,
> {
    pub delegations: Vec<Arc<Signed<Delegation<F, S, K, T, L>>>>,
    pub revocations: Vec<Arc<Signed<Revocation<F, S, K, T, L>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
