use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::AsyncSigner},
    listener::membership::MembershipListener,
    principal::group::delegation::{Delegation, StaticDelegation},
};
use derive_where::derive_where;
use future_form::FutureForm;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Hash)]
#[derive_where(Clone; U)]
pub struct Invocation<K: FutureForm + ?Sized, S: AsyncSigner, C: ContentRef, L: MembershipListener<K, S, C>, U: Clone = C> {
    pub(crate) invoke: U,
    pub(crate) proof: Option<Arc<Signed<Delegation<K, S, C, L>>>>,
}

impl<K: FutureForm + ?Sized, S: AsyncSigner, C: ContentRef, L: MembershipListener<K, S, C>, U: Clone + Serialize> Serialize
    for Invocation<K, S, C, L, U>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        StaticInvocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticInvocation<C: ContentRef, U: Clone> {
    pub(crate) invoke: U,
    pub(crate) proof: Option<Digest<Signed<StaticDelegation<C>>>>,
}

impl<K: FutureForm + ?Sized, S: AsyncSigner, C: ContentRef, L: MembershipListener<K, S, C>, U: Clone>
    From<Invocation<K, S, C, L, U>> for StaticInvocation<C, U>
{
    fn from(invocation: Invocation<K, S, C, L, U>) -> Self {
        let invoke = invocation.invoke;
        let proof = invocation
            .proof
            .map(|proof| Digest::hash(proof.as_ref()).into());

        Self { invoke, proof }
    }
}
