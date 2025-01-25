use crate::{
    content::reference::ContentRef,
    crypto::signed::Signed,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        group::{
            delegation::{Delegation, StaticDelegation},
            membership_operation::MembershipOperation,
            revocation::{Revocation, StaticRevocation},
        },
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
    },
};
use derive_more::{From, TryInto};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, Clone, Dupe, PartialEq, Eq, From, TryInto, Hash)]
pub enum Event<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    // Prekeys
    PrekeysExpanded(Rc<Signed<AddKeyOp>>),
    PrekeyRotated(Rc<Signed<RotateKeyOp>>),

    // Cgka
    // TODO!

    // Membership
    Delegated(Rc<Signed<Delegation<T, L>>>),
    Revoked(Rc<Signed<Revocation<T, L>>>),
}

impl<T: ContentRef, L: MembershipListener<T>> Serialize for Event<T, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        StaticEvent::from(self.clone()).serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, From, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    // Prekeys
    PrekeysExpanded(Signed<AddKeyOp>),
    PrekeyRotated(Signed<RotateKeyOp>),

    // Cgka
    // TODO!

    // Membership
    Delegated(Signed<StaticDelegation<T>>),
    Revoked(Signed<StaticRevocation<T>>),
}

impl<T: ContentRef, L: MembershipListener<T>> From<KeyOp> for Event<T, L> {
    fn from(key_op: KeyOp) -> Self {
        match key_op {
            KeyOp::Add(add) => Event::PrekeysExpanded(add),
            KeyOp::Rotate(rot) => Event::PrekeyRotated(rot),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<MembershipOperation<T, L>> for Event<T, L> {
    fn from(op: MembershipOperation<T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => Event::Delegated(d),
            MembershipOperation::Revocation(r) => Event::Revoked(r),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Event<T, L>> for StaticEvent<T> {
    fn from(op: Event<T, L>) -> Self {
        match op {
            Event::Delegated(d) => StaticEvent::Delegated(Rc::unwrap_or_clone(d).map(Into::into)),
            Event::Revoked(r) => StaticEvent::Revoked(Rc::unwrap_or_clone(r).map(Into::into)),
            Event::PrekeyRotated(pkr) => {
                StaticEvent::PrekeyRotated(Rc::unwrap_or_clone(pkr).map(Into::into))
            }
            Event::PrekeysExpanded(pke) => {
                StaticEvent::PrekeysExpanded(Rc::unwrap_or_clone(pke).map(Into::into))
            }
        }
    }
}
