use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::group::delegation::{Delegation, StaticDelegation},
};
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Invocation<C: ContentRef = [u8; 32], L: MembershipListener<C> = NoListener, T: Clone = C>
{
    pub(crate) invoke: T,
    pub(crate) proof: Option<Rc<Signed<Delegation<C, L>>>>,
}

impl<C: ContentRef, L: MembershipListener<C>, T: Clone> Serialize for Invocation<C, L, T>
where
    T: Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StaticInvocation::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StaticInvocation<C: ContentRef, T: Clone> {
    pub(crate) invoke: T,
    pub(crate) proof: Option<Digest<Signed<StaticDelegation<C>>>>,
}

impl<C: ContentRef, L: MembershipListener<C>, T: Clone> From<Invocation<C, L, T>>
    for StaticInvocation<C, T>
{
    fn from(invocation: Invocation<C, L, T>) -> Self {
        let invoke = invocation.invoke;
        let proof = invocation
            .proof
            .map(|proof| Digest::hash(proof.as_ref()).into());

        Self { invoke, proof }
    }
}
