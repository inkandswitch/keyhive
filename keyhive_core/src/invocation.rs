use crate::{
    crypto::digest::Digest,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::{Delegation, StaticDelegation},
};
use derive_where::derive_where;
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Hash)]
#[derive_where(Clone; T)]
pub struct Invocation<
    F: FutureForm,
    S: AsyncSigner<F>,
    C: ContentRef = [u8; 32],
    L: MembershipListener<F, S, C> = NoListener,
    T: Clone = C,
> {
    pub(crate) invoke: T,
    pub(crate) proof: Option<Arc<Signed<Delegation<F, S, C, L>>>>,
}

impl<
        F: FutureForm,
        S: AsyncSigner<F>,
        C: ContentRef,
        L: MembershipListener<F, S, C>,
        T: Clone + Serialize,
    > Serialize for Invocation<F, S, C, L, T>
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

impl<F: FutureForm, S: AsyncSigner<F>, C: ContentRef, L: MembershipListener<F, S, C>, T: Clone>
    From<Invocation<F, S, C, L, T>> for StaticInvocation<C, T>
{
    fn from(invocation: Invocation<F, S, C, L, T>) -> Self {
        let invoke = invocation.invoke;
        let proof = invocation
            .proof
            .map(|proof| Digest::hash(proof.as_ref()).coerce());

        Self { invoke, proof }
    }
}
