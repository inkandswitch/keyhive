use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner, share_key::ShareSecretStore},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::{Delegation, StaticDelegation},
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq, Hash)]
#[derive_where(Clone; T)]
pub struct Invocation<
    S: AsyncSigner,
    K: ShareSecretStore,
    C: ContentRef = [u8; 32],
    L: MembershipListener<S, K, C> = NoListener,
    T: Clone = C,
> {
    pub(crate) invoke: T,
    pub(crate) proof: Option<Rc<Signed<Delegation<S, K, C, L>>>>,
}

impl<S: AsyncSigner, K: ShareSecretStore, C: ContentRef, L: MembershipListener<S, K, C>, T: Clone + Serialize> Serialize
    for Invocation<S, K, C, L, T>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticInvocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticInvocation<C: ContentRef, T: Clone> {
    pub(crate) invoke: T,
    pub(crate) proof: Option<Digest<Signed<StaticDelegation<C>>>>,
}

impl<S: AsyncSigner, K: ShareSecretStore, C: ContentRef, L: MembershipListener<S, K, C>, T: Clone>
    From<Invocation<S, K, C, L, T>> for StaticInvocation<C, T>
{
    fn from(invocation: Invocation<S, K, C, L, T>) -> Self {
        let invoke = invocation.invoke;
        let proof = invocation
            .proof
            .map(|proof| Digest::hash(proof.as_ref()).into());

        Self { invoke, proof }
    }
}
