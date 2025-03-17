use crate::{
    content::reference::ContentRef,
    crypto::{
        digest::Digest, encrypted::EncryptedContent, envelope::Envelope,
        symmetric_key::SymmetricKey,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[trait_variant::make(SendableCiphertextStore: Send)]
pub trait CiphertextStore<T, Cr: ContentRef> {
    async fn get(&self, id: &Digest<Cr>) -> Option<EncryptedContent<T, Cr>>;
}

pub async fn try_sendable_causal_decrypt<
    T: Send,
    Cr: ContentRef + Send,
    S: SendableCiphertextStore<T, Cr>,
>(
    store: &S,
    to_decrypt: &mut Vec<(EncryptedContent<T, Cr>, SymmetricKey)>,
) -> Result<CausalDecryptionState<T, Cr>, CausalDecryptionError<T, Cr>>
where
    T: Serialize + DeserializeOwned + Clone,
    Cr: DeserializeOwned,
{
    try_causal_decrypt(store, to_decrypt).await
}

pub async fn try_causal_decrypt<T, Cr: ContentRef, S: CiphertextStore<T, Cr>>(
    store: &S,
    to_decrypt: &mut Vec<(EncryptedContent<T, Cr>, SymmetricKey)>,
) -> Result<CausalDecryptionState<T, Cr>, CausalDecryptionError<T, Cr>>
where
    T: Serialize + DeserializeOwned + Clone,
    Cr: DeserializeOwned,
{
    let mut acc = CausalDecryptionState::new();
    let mut seen = HashSet::new();

    while let Some((ciphertext, key)) = to_decrypt.pop() {
        if !seen.insert(ciphertext.content_ref) {
            continue;
        }

        if let Ok(decrypted) = ciphertext.try_decrypt(key) {
            let envelope: Envelope<Cr, T> =
                bincode::deserialize(decrypted.as_slice()).map_err(|e| CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        ciphertext.content_ref,
                        ErrorReason::DeserializationFailed(e.into()),
                    )]),
                })?;

            for (ancestor_hash, ancestor_key) in envelope.ancestors.iter() {
                let ancestor =
                    store
                        .get(&Digest::hash(ancestor_hash))
                        .await
                        .ok_or(CausalDecryptionError {
                            progress: acc.clone(),
                            cannot: HashMap::from_iter([(
                                ciphertext.content_ref,
                                ErrorReason::CannotFindCiphertext(ancestor_hash.clone()),
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

#[derive(Debug, Clone)]
pub struct CausalDecryptionState<T, Cr: ContentRef> {
    pub complete: Vec<(Digest<Cr>, T)>,
    pub keys: HashMap<Digest<Cr>, SymmetricKey>,
    pub next: HashMap<Digest<Cr>, SymmetricKey>,
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
    pub cannot: HashMap<Digest<Cr>, ErrorReason<Cr>>,
    pub progress: CausalDecryptionState<T, Cr>,
}

#[derive(Debug, Error)]
pub enum ErrorReason<Cr: ContentRef> {
    #[error("Decryption failed")]
    DecryptionFailed(SymmetricKey),

    #[error(transparent)]
    DeserializationFailed(Box<bincode::Error>),

    #[error("Cannot find ciphertext: {0}")]
    CannotFindCiphertext(Cr),
}
