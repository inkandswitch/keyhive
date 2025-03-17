use crate::{
    content::reference::ContentRef,
    crypto::{encrypted::EncryptedContent, envelope::Envelope, symmetric_key::SymmetricKey},
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use thiserror::Error;

#[allow(async_fn_in_trait)]
pub trait CiphertextStore<T, Cr: ContentRef> {
    async fn get(&self, id: &Cr) -> Option<EncryptedContent<T, Cr>>;

    async fn try_causal_decrypt(
        &self,
        to_decrypt: &mut Vec<(EncryptedContent<T, Cr>, SymmetricKey)>,
    ) -> Result<CausalDecryptionState<T, Cr>, CausalDecryptionError<T, Cr>>
    where
        T: Serialize + DeserializeOwned + Clone,
        Cr: DeserializeOwned,
    {
        let mut acc = CausalDecryptionState::new();
        let mut seen = HashSet::new();

        while let Some((ciphertext, key)) = to_decrypt.pop() {
            if !seen.insert(ciphertext.content_ref.clone()) {
                continue;
            }

            if let Ok(decrypted) = ciphertext.try_decrypt(key) {
                let envelope: Envelope<Cr, T> = bincode::deserialize(decrypted.as_slice())
                    .map_err(|e| CausalDecryptionError {
                        progress: acc.clone(),
                        cannot: HashMap::from_iter([(
                            ciphertext.content_ref.clone(),
                            ErrorReason::DeserializationFailed(e.into()),
                        )]),
                    })?;

                for (ancestor_ref, ancestor_key) in envelope.ancestors.iter() {
                    let ancestor = self.get(&ancestor_ref).await.ok_or(CausalDecryptionError {
                        progress: acc.clone(),
                        cannot: HashMap::from_iter([(
                            ciphertext.content_ref.clone(),
                            ErrorReason::CannotFindCiphertext(ancestor_ref.clone()),
                        )]),
                    })?;
                    to_decrypt.push((ancestor, *ancestor_key));
                }

                acc.complete
                    .push((ciphertext.content_ref, envelope.plaintext));
            } else {
                Err(CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        ciphertext.content_ref,
                        ErrorReason::DecryptionFailed(key),
                    )]),
                })?;
            }
        }

        Ok(acc)
    }
}

pub trait SendableCiphertextStore<T: Send, Cr: ContentRef + Send>: CiphertextStore<T, Cr> {
    fn get_sendable(&self, id: &Cr)
        -> impl Future<Output = Option<EncryptedContent<T, Cr>>> + Send;

    #[allow(async_fn_in_trait)]
    async fn try_sendable_causal_decrypt(
        &self,
        to_decrypt: &mut Vec<(EncryptedContent<T, Cr>, SymmetricKey)>,
    ) -> Result<CausalDecryptionState<T, Cr>, CausalDecryptionError<T, Cr>>
    where
        T: Serialize + DeserializeOwned + Clone,
        Cr: DeserializeOwned,
    {
        let mut acc = CausalDecryptionState::new();
        let mut seen = HashSet::new();

        while let Some((ciphertext, key)) = to_decrypt.pop() {
            if !seen.insert(ciphertext.content_ref.clone()) {
                continue;
            }

            if let Ok(decrypted) = ciphertext.try_decrypt(key) {
                let envelope: Envelope<Cr, T> = bincode::deserialize(decrypted.as_slice())
                    .map_err(|e| CausalDecryptionError {
                        progress: acc.clone(),
                        cannot: HashMap::from_iter([(
                            ciphertext.content_ref.clone(),
                            ErrorReason::DeserializationFailed(e.into()),
                        )]),
                    })?;

                for (ancestor_ref, ancestor_key) in envelope.ancestors.iter() {
                    let ancestor =
                        self.get_sendable(&ancestor_ref)
                            .await
                            .ok_or(CausalDecryptionError {
                                progress: acc.clone(),
                                cannot: HashMap::from_iter([(
                                    ciphertext.content_ref.clone(),
                                    ErrorReason::CannotFindCiphertext(ancestor_ref.clone()),
                                )]),
                            })?;
                    to_decrypt.push((ancestor, *ancestor_key));
                }

                acc.complete
                    .push((ciphertext.content_ref, envelope.plaintext));
            } else {
                Err(CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        ciphertext.content_ref,
                        ErrorReason::DecryptionFailed(key),
                    )]),
                })?;
            }
        }

        Ok(acc)
    }
}

#[derive(Debug, Clone)]
pub struct CausalDecryptionState<T, Cr: ContentRef> {
    pub complete: Vec<(Cr, T)>,
    pub keys: HashMap<Cr, SymmetricKey>,
    pub next: HashMap<Cr, SymmetricKey>,
}

impl<T, Cr: ContentRef> CausalDecryptionState<T, Cr> {
    pub fn new() -> Self {
        CausalDecryptionState {
            complete: vec![],
            keys: HashMap::new(),
            next: HashMap::new(),
        }
    }
}

#[derive(Debug, Error)]
#[error("Causal decryption error: {cannot}")]
pub struct CausalDecryptionError<T, Cr: ContentRef> {
    pub cannot: HashMap<Cr, ErrorReason<Cr>>,
    pub progress: CausalDecryptionState<T, Cr>,
}

#[derive(Debug, Error)]
pub enum ErrorReason<Cr: ContentRef> {
    #[error("Decryption failed")]
    DecryptionFailed(SymmetricKey),

    #[error(transparent)]
    DeserializationFailed(Box<bincode::Error>),

    #[error("Cannot find ciphertext for ref")]
    CannotFindCiphertext(Cr),
}
