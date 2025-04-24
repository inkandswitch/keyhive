use super::{delegation::Delegation, revocation::Revocation};
use crate::{
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::document::id::DocumentId,
    store::secret_key::traits::ShareSecretStore,
};
use std::{collections::BTreeMap, hash::Hash, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dependencies<
    'a,
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub delegations: Vec<Rc<Signed<Delegation<S, K, T, L>>>>,
    pub revocations: Vec<Rc<Signed<Revocation<S, K, T, L>>>>,
    pub content: &'a BTreeMap<DocumentId, Vec<T>>,
}
