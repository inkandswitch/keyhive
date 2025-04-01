//! Serializable version of [`Event`][super::Event].

use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::Signed,
    },
    principal::{
        document::id::DocumentId,
        group::{delegation::StaticDelegation, revocation::StaticRevocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::{From, TryInto};
use serde::{Deserialize, Serialize};

use super::wire_event::WireEvent;

/// Serailizable version of [`Event`][super::Event].
///
/// These events MUST NOT be put on the network. If you need a
/// serializable event to put on the network, use [`WireEvent`][super::WireEvent].
#[derive(Debug, Clone, PartialEq, Eq, From, TryInto, Serialize, Deserialize)]
pub enum StaticEvent<T: ContentRef = [u8; 32]> {
    /// Prekeys were expanded.
    PrekeysExpanded(Signed<AddKeyOp>),

    /// A prekey was rotated.
    PrekeyRotated(Signed<RotateKeyOp>),

    /// A CGKA operation was performed.
    CgkaOperation(Signed<CgkaOperation>),

    /// A delegation was created.
    Delegated(Signed<StaticDelegation<T>>),

    /// A delegation was revoked.
    Revoked(Signed<StaticRevocation<T>>),

    // TODO comment: do not add to static event
    DocumentSecret {
        doc_id: DocumentId,
        public_key: ShareKey,
        secret_key: ShareSecretKey,
    },

    // TODO comment: do not add to static event
    ActiveAgentSecret {
        public_key: ShareKey,
        secret_key: ShareSecretKey,
    },
}

impl From<WireEvent> for StaticEvent {
    fn from(event: WireEvent) -> Self {
        match event {
            WireEvent::PrekeysExpanded(e) => Self::PrekeysExpanded(e),
            WireEvent::PrekeyRotated(e) => Self::PrekeyRotated(e),
            WireEvent::CgkaOperation(e) => Self::CgkaOperation(e),
            WireEvent::Delegated(e) => Self::Delegated(e),
            WireEvent::Revoked(e) => Self::Revoked(e),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T: arbitrary::Arbitrary<'a> + ContentRef> arbitrary::Arbitrary<'a> for StaticEvent<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant = u.int_in_range(0..=4)?;
        match variant {
            0 => Ok(Self::PrekeysExpanded(Signed::arbitrary(u)?)),
            1 => Ok(Self::PrekeyRotated(Signed::arbitrary(u)?)),
            2 => Ok(Self::CgkaOperation(Signed::arbitrary(u)?)),
            3 => Ok(Self::Delegated(Signed::arbitrary(u)?)),
            4 => Ok(Self::Revoked(Signed::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}
