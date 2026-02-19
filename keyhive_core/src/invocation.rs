use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, signer::async_signer::{AsyncSigner, AsyncSignerLocal, AsyncSignerSend}},
    listener::membership::MembershipListener,
    principal::group::delegation::{Delegation, StaticDelegation},
};
use derive_where::derive_where;
use future_form::{FutureForm, Local, Sendable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Hash)]
#[derive_where(Clone; U)]
pub struct Invocation<K: FutureForm + ?Sized, S: AsyncSigner<K>, C: ContentRef, L: MembershipListener<K, S, C>, U: Clone = C> {
    pub(crate) invoke: U,
    pub(crate) proof: Option<Arc<Signed<Delegation<K, S, C, L>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticInvocation<C: ContentRef, U: Clone> {
    pub(crate) invoke: U,
    pub(crate) proof: Option<Digest<Signed<StaticDelegation<C>>>>,
}

macro_rules! impl_invocation {
    (sendable) => {
        impl<S: AsyncSignerSend + Send + Sync, C: ContentRef, L: MembershipListener<Sendable, S, C> + Send + Sync, U: Clone + Serialize> Serialize
            for Invocation<Sendable, S, C, L, U>
        {
            fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
                StaticInvocation::from(self.clone()).serialize(serializer)
            }
        }

        impl<S: AsyncSignerSend + Send + Sync, C: ContentRef, L: MembershipListener<Sendable, S, C> + Send + Sync, U: Clone>
            From<Invocation<Sendable, S, C, L, U>> for StaticInvocation<C, U>
        {
            fn from(invocation: Invocation<Sendable, S, C, L, U>) -> Self {
                let invoke = invocation.invoke;
                let proof = invocation
                    .proof
                    .map(|proof| Digest::hash(proof.as_ref()).into());

                Self { invoke, proof }
            }
        }
    };
    (local) => {
        impl<S: AsyncSignerLocal, C: ContentRef, L: MembershipListener<Local, S, C>, U: Clone + Serialize> Serialize
            for Invocation<Local, S, C, L, U>
        {
            fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
                StaticInvocation::from(self.clone()).serialize(serializer)
            }
        }

        impl<S: AsyncSignerLocal, C: ContentRef, L: MembershipListener<Local, S, C>, U: Clone>
            From<Invocation<Local, S, C, L, U>> for StaticInvocation<C, U>
        {
            fn from(invocation: Invocation<Local, S, C, L, U>) -> Self {
                let invoke = invocation.invoke;
                let proof = invocation
                    .proof
                    .map(|proof| Digest::hash(proof.as_ref()).into());

                Self { invoke, proof }
            }
        }
    };
}

impl_invocation!(sendable);
impl_invocation!(local);
