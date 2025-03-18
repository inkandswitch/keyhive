use crate::{
    content::reference::ContentRef,
    crypto::{encrypted::EncryptedContent, envelope::Envelope, symmetric_key::SymmetricKey},
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use thiserror::Error;

pub trait CiphertextStore<T, Cr: ContentRef> {
    type WorkFuture<'a>: Future<Output = Option<EncryptedContent<T, Cr>>>
    where
        Self: 'a,
        Cr: 'a;

    fn get<'a>(&'a self, id: &'a Cr) -> Self::WorkFuture<'a>;

    #[allow(async_fn_in_trait)]
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

#[cfg(test)]
mod tests {
    use super::*;

    mod sendable {
        use super::*;
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone)]
        struct Foo<T: Send, Cr: ContentRef + Send + Sync>(
            Arc<tokio::sync::Mutex<HashMap<Cr, EncryptedContent<T, Cr>>>>,
        );

        impl<T: Send + Clone, Cr: ContentRef + Send + Sync> CiphertextStore<T, Cr> for Foo<T, Cr> {
            type WorkFuture<'a>
                = Pin<Box<dyn Future<Output = Option<EncryptedContent<T, Cr>>> + Send + 'a>>
            where
                Self: 'a,
                Cr: 'a;

            fn get<'a>(&'a self, id: &'a Cr) -> Self::WorkFuture<'a> {
                Box::pin(async move { self.0.lock().await.get(&id).cloned() })
            }
        }
    }
}
