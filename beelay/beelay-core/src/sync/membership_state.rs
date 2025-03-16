use std::{collections::HashMap, rc::Rc};

use keyhive_core::{
    crypto::{digest::Digest, signer::memory::MemorySigner},
    event::{static_event::StaticEvent, Event},
    listener::no_listener::NoListener,
    principal::{
        group::membership_operation::MembershipOperation, identifier::Identifier,
        individual::op::KeyOp,
    },
};

use crate::{keyhive::Listener, CommitHash, PeerId, Signer, TaskContext};

#[derive(Clone)]
pub(crate) struct MembershipState {
    membership_ops: HashMap<
        Digest<MembershipOperation<Signer, CommitHash, Listener>>,
        MembershipOperation<Signer, CommitHash, Listener>,
    >,
    prekey_ops: HashMap<Identifier, Vec<Rc<KeyOp>>>,
}

impl MembershipState {
    pub(crate) fn empty() -> Self {
        Self {
            membership_ops: HashMap::new(),
            prekey_ops: HashMap::new(),
        }
    }

    pub(crate) async fn load<R: rand::Rng + rand::CryptoRng>(
        ctx: TaskContext<R>,
        remote: PeerId,
    ) -> Self {
        Self {
            membership_ops: ctx.state().keyhive().membership_ops_for_peer(remote).await,
            prekey_ops: ctx.state().keyhive().prekey_ops_for_peer(remote).await,
        }
    }

    pub(crate) fn into_static_events(
        self,
    ) -> HashMap<Digest<StaticEvent<CommitHash>>, StaticEvent<CommitHash>> {
        self.membership_ops
            .into_values()
            .map(|op| StaticEvent::from(Event::from(op)))
            .chain(self.prekey_ops.into_values().flat_map(|ops| {
                ops.into_iter().map(|op| {
                    StaticEvent::from(Event::<MemorySigner, CommitHash, NoListener>::from(
                        Rc::unwrap_or_clone(op),
                    ))
                })
            }))
            .map(|op| (Digest::hash(&op), op))
            .collect()
    }
}
