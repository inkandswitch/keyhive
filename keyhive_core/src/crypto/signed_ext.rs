//! Extension traits for [`SerdeSigned`] that add keyhive_core-specific methods.
//!
//! These traits exist because [`SerdeSigned`] is defined in [`keyhive_crypto`],
//! so keyhive_core cannot add inherent methods to it directly (orphan rule).

use crate::{
    listener::membership::MembershipListener,
    principal::group::{delegation::Delegation, revocation::Revocation},
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, identifier::Identifier, signed::SerdeSigned,
    signer::async_signer::AsyncSigner,
};

/// Retrieve the issuer [`Identifier`] from any [`SerdeSigned<T>`].
pub trait SignedId {
    fn id(&self) -> Identifier;
}

impl<T: serde::Serialize + std::fmt::Debug> SignedId for SerdeSigned<T> {
    fn id(&self) -> Identifier {
        self.issuer
    }
}

/// Retrieve the subject [`Identifier`] for delegation and revocation chains.
///
/// For a [`SerdeSigned<Delegation>`], this walks the proof chain to find the root
/// issuer. For a [`SerdeSigned<Revocation>`], this delegates to the revoked
/// delegation's subject.
pub trait SignedSubjectId {
    fn subject_id(&self) -> Identifier;
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    SignedSubjectId for SerdeSigned<Delegation<F, S, T, L>>
{
    fn subject_id(&self) -> Identifier {
        let mut head = self;

        while let Some(proof) = &head.payload.proof {
            head = proof;
        }

        head.issuer
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    SignedSubjectId for SerdeSigned<Revocation<F, S, T, L>>
{
    fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}
