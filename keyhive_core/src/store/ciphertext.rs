use crate::{
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::{CausalDecryptionError, CausalDecryptionState, EncryptedContent, Reason},
        envelope::Envelope,
        symmetric_key::SymmetricKey,
    },
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};

// FIXME feature flag
#[trait_variant::make(SendableCiphertextStore: Send)]
pub trait CiphertextStore<T: Send, Cr: ContentRef + Send> {
    async fn get(&self, id: &Digest<Cr>) -> Option<EncryptedContent<T, Cr>>;

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
            if !seen.insert(ciphertext.content_ref) {
                continue;
            }

            if let Ok(decrypted) = ciphertext.try_decrypt(key) {
                let envelope: Envelope<Cr, T> = bincode::deserialize(decrypted.as_slice())
                    .map_err(|e| CausalDecryptionError {
                        progress: acc.clone(),
                        cannot: HashMap::from_iter([(
                            ciphertext.content_ref,
                            Reason::DeserializationFailed(e.into()),
                        )]),
                    })?;

                for (ancestor_hash, ancestor_key) in envelope.ancestors.iter() {
                    let ancestor = self.get(&Digest::hash(ancestor_hash)).await.expect("FIXME");
                    to_decrypt.push((ancestor, *ancestor_key));
                }

                acc.complete
                    .push((ciphertext.content_ref, envelope.plaintext));
            } else {
                Err(CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        ciphertext.content_ref,
                        Reason::DecryptionFailed(key),
                    )]),
                })?;
            }
        }

        Ok(acc)
    }
}
