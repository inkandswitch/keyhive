//! Extension traits for [`Signed`] that add keyhive_core-specific methods.
//!
//! These traits exist because [`Signed`] is defined in [`keyhive_crypto`],
//! so keyhive_core cannot add inherent methods to it directly (orphan rule).

use crate::store::secret_key::SecretKeyStore;
use crate::{
    listener::membership::MembershipListener,
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        identifier::Identifier,
    },
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
    verifiable::Verifiable,
};

/// Retrieve the issuer [`Identifier`] from any [`Signed<T>`].
pub trait SignedId {
    fn id(&self) -> Identifier;
}

impl<T: serde::Serialize + std::fmt::Debug> SignedId for Signed<T> {
    fn id(&self) -> Identifier {
        self.verifying_key().into()
    }
}

/// Retrieve the subject [`Identifier`] for delegation and revocation chains.
///
/// For a [`Signed<Delegation>`], this walks the proof chain to find the root
/// issuer. For a [`Signed<Revocation>`], this delegates to the revoked
/// delegation's subject.
pub trait SignedSubjectId {
    fn subject_id(&self) -> Identifier;
}

impl<
        F: FutureForm,
        S: AsyncSigner<F>,
        K: SecretKeyStore<F>,
        T: ContentRef,
        L: MembershipListener<F, S, K, T>,
    > SignedSubjectId for Signed<Delegation<F, S, K, T, L>>
{
    fn subject_id(&self) -> Identifier {
        let mut head = self;

        while let Some(proof) = &head.payload.proof {
            head = proof;
        }

        head.issuer.into()
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F>,
        K: SecretKeyStore<F>,
        T: ContentRef,
        L: MembershipListener<F, S, K, T>,
    > SignedSubjectId for Signed<Revocation<F, S, K, T, L>>
{
    fn subject_id(&self) -> Identifier {
        self.payload.subject_id()
    }
}
