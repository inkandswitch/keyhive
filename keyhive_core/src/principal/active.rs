//! The current user agent (which can sign and encrypt).

pub mod archive;

use self::archive::ActiveArchive;
use super::{
    document::id::DocumentId,
    identifier::Identifier,
    individual::{
        id::IndividualId,
        op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
        state::PrekeyState,
        Individual,
    },
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        signer::async_signer::AsyncSigner,
        verifiable::Verifiable,
    },
    listener::{no_listener::NoListener, prekey::PrekeyListener},
    principal::{
        agent::id::AgentId,
        group::delegation::{Delegation, DelegationError},
        membered::Membered,
    },
};
use derivative::Derivative;
use futures::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug, Hash, PartialEq)]
pub struct Active<S: AsyncSigner, L: PrekeyListener = NoListener> {
    /// The signing key of the active agent.
    #[derivative(Debug = "ignore")]
    pub(crate) signer: S,

    // TODO generalize to use e.g. KMS for X25519 secret keys
    #[derivative(
        Debug(format_with = "crate::util::debug::prekey_fmt"),
        Hash(hash_with = "crate::util::hasher::keys"),
        PartialEq(compare_with = "crate::util::partial_eq::prekey_partial_eq")
    )]
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,

    ///The listener for prekey events.
    #[serde(skip)]
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub(crate) listener: L,
}

impl<S: AsyncSigner, L: PrekeyListener> Active<S, L> {
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: S,
        listener: L,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let init_sk = ShareSecretKey::generate(csprng);
        let init_pk = init_sk.share_key();
        let init_op = Rc::new(
            signer
                .try_sign_async(AddKeyOp { share_key: init_pk })
                .await?,
        )
        .into();

        let mut prekey_state = PrekeyState::new(init_op);
        let prekey_pairs =
            (0..6).try_fold(BTreeMap::from_iter([(init_pk, init_sk)]), |mut acc, _| {
                let sk = ShareSecretKey::generate(csprng);
                let pk = sk.share_key();
                acc.insert(pk, sk);
                Ok::<_, SigningError>(acc)
            })?;

        let borrowed_signer = &signer;
        let ops = stream::iter(prekey_pairs.keys().map(|x| Ok::<_, SigningError>(x)))
            .try_fold(vec![], |mut acc, pk| async move {
                acc.push(
                    Rc::new(
                        borrowed_signer
                            .try_sign_async(AddKeyOp { share_key: *pk })
                            .await?,
                    )
                    .into(),
                );
                Ok(acc)
            })
            .await?;

        prekey_state
            .extend(ops)
            .expect("newly generated local op should be valid");

        Ok(Self {
            individual: Individual {
                id: signer.verifying_key().into(),
                prekeys: prekey_state.build(),
                prekey_state,
            },
            prekey_pairs,
            listener,
            signer,
        })
    }

    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    pub fn individual(&self) -> &Individual {
        &self.individual
    }

    pub fn pick_prekey(&self, doc_id: DocumentId) -> Option<ShareKey> {
        self.individual.pick_prekey(doc_id)
    }

    pub async fn rotate_prekey<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old_prekey: ShareKey,
        csprng: &mut R,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        let op = self
            .individual
            .rotate_prekey(old_prekey, &self.signer, csprng)
            .await?;
        self.listener.on_prekey_rotated(&op).await;
        Ok(op)
    }

    pub async fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        let op = self.individual.expand_prekeys(&self.signer, csprng).await?;
        self.listener.on_prekeys_expanded(&op).await;
        Ok(op)
    }

    /// Sign a payload.
    pub async fn try_sign_async<U: Serialize>(
        &self,
        payload: U,
    ) -> Result<Signed<U>, SigningError> {
        self.signer.try_sign_async(payload).await
    }

    pub fn get_capability<T: ContentRef>(
        &self,
        subject: Membered<S, T>,
        min: Access,
    ) -> Option<Rc<Signed<Delegation<S, T>>>> {
        subject.get_capability(&self.id().into()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    pub fn into_archive(&self) -> ActiveArchive {
        ActiveArchive {
            prekey_pairs: self.prekey_pairs.clone(),
            individual: self.individual.clone(),
        }
    }

    pub fn from_archive(archive: &ActiveArchive, signer: S, listener: L) -> Self {
        Self {
            prekey_pairs: archive.prekey_pairs.clone(),
            individual: archive.individual.clone(),
            signer,
            listener,
        }
    }
}

impl<S: AsyncSigner, L: PrekeyListener> std::fmt::Display for Active<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<S: AsyncSigner, L: PrekeyListener> Verifiable for Active<S, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifying_key()
    }
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("The active agent cannot find a public ShareKey for themselves")]
    MissingYourSharePublicKey,

    #[error("The active agent cannot find a secret ShareKey for themselves")]
    MissingYourShareSecretKey,

    #[error("The active agent does not know the ShareKey for the recipient: {0}")]
    MissingRecipientShareKey(Identifier),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error("Siv error: {0}")]
    SivError(std::io::Error),
}

#[derive(Debug, Error)]
pub enum ActiveDelegationError {
    #[error("Cannot find proof at the requested access level")]
    CannotFindProof,

    #[error(transparent)]
    DelegationError(#[from] DelegationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_seal() {
        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let active = Active::generate(signer, NoListener, csprng).await.unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign_async(message).await.unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
