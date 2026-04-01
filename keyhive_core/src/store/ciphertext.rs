//! A store for encrypted content plus some metadata.

pub mod memory;

use self::memory::MemoryCiphertextStore;
use crate::crypto::{digest::Digest, envelope::Envelope};
use beekem::{encrypted::EncryptedContent, operation::CgkaOperation};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_crypto::{content::reference::ContentRef, signed::Signed, symmetric_key::SymmetricKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt::{Debug, Display},
    sync::Arc,
};
use thiserror::Error;

/// An async storage interface for ciphertexts.
///
/// The `F: FutureForm` parameter determines whether the returned
/// futures are `Send` ([`Sendable`](future_form::Sendable)) or
/// `!Send` ([`Local`](future_form::Local)).
///
/// This includes functionality for "causal decryption":
/// the ability to decrypt a set of causally-related ciphertexts.
/// See [`try_causal_decrypt`][CiphertextStoreExt::try_causal_decrypt] for more information.
///
/// The `get_ciphertext` method generally fails on items that have already been decrypted.
/// This is generally accomplished by either removing the decrypted values from the store,
/// or — more commonly — by tracking which values have been decrypted and simply not
/// hitting the backing store on requests for those IDs.
pub trait CiphertextStore<F: FutureForm, Cr: ContentRef, T>: Sized {
    type GetCiphertextError: Debug + Display;
    type MarkDecryptedError: Debug + Display;

    fn get_ciphertext<'a>(
        &'a self,
        id: &'a Cr,
    ) -> F::Future<'a, Result<Option<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>>;

    fn get_ciphertext_by_pcs_update<'a>(
        &'a self,
        pcs_update: &'a Digest<Signed<CgkaOperation>>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>>;

    fn mark_decrypted<'a>(
        &'a self,
        id: &'a Cr,
    ) -> F::Future<'a, Result<(), Self::MarkDecryptedError>>;
}

/// Extension trait providing [`try_causal_decrypt`] for all
/// [`CiphertextStore`] implementations.
///
/// This is a separate trait because the default method body uses
/// `F::from_future(async { ... })` which requires concrete `F`
/// (either [`Sendable`] or [`Local`]). The `#[future_form]` macro
/// stamps out both variants via a blanket impl.
///
/// [`try_causal_decrypt`]: CiphertextStoreExt::try_causal_decrypt
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
pub trait CiphertextStoreExt<F: FutureForm, Cr: ContentRef, T>: CiphertextStore<F, Cr, T> {
    #[cfg_attr(all(doc, feature = "mermaid_docs"), aquamarine::aquamarine)]
    /// Recursively decrypts a set of causally-related ciphertexts.
    ///
    /// Consider the following causally encrypted graph:
    ///
    /// ```mermaid
    /// flowchart
    ///     subgraph genesis["oUz 🔓"]
    ///       a[New Doc]
    ///     end
    ///
    ///     subgraph block1["g6z 🔓"]
    ///       op1[Op 1]
    ///
    ///       subgraph block1ancestors[Ancestors]
    ///         subgraph block1ancestor1[Ancestor 1]
    ///           pointer1_1["Pointer #️⃣"]
    ///           key1_1["Key 🔑"]
    ///         end
    ///       end
    ///     end
    ///
    ///     pointer1_1 --> genesis
    ///
    ///     subgraph block2["Xa2 🔓"]
    ///         op2[Op 2]
    ///         op3[Op 3]
    ///         op4[Op 4]
    ///
    ///       subgraph block2ancestors[Ancestors]
    ///         subgraph block2ancestor1[Ancestor 1]
    ///           pointer2_1["Pointer #️⃣"]
    ///           key2_1["Key 🔑"]
    ///         end
    ///       end
    ///     end
    ///
    ///     pointer2_1 --> genesis
    ///
    ///     subgraph block3["e9j 🔓"]
    ///       op5[Op 5]
    ///       op6[Op 6]
    ///
    ///       subgraph block3ancestors[Ancestors]
    ///         subgraph block3ancestor1[Ancestor 1]
    ///           pointer3_1["Pointer #️⃣"]
    ///           key3_1["Key 🔑"]
    ///         end
    ///
    ///         subgraph block3ancestor2[Ancestor 2]
    ///           pointer3_2["Pointer #️⃣"]
    ///           key3_2["Key 🔑"]
    ///         end
    ///       end
    ///     end
    ///
    ///     pointer3_1 --> block1
    ///     pointer3_2 --> block2
    ///
    ///     subgraph head[Read Capabilty]
    ///       pointer_head["Pointer #️⃣"]
    ///       key_head["Key 🔑"]
    ///     end
    ///
    ///     pointer_head --> block3
    /// ```
    ///
    /// By passing in the entrypoint, futher keys are discovered, and can be pulled out
    /// the store, which contain more keys and references, and so on.
    ///
    /// It is normal for this to stop decryption if it encounters an already-decrypted
    /// ciphertext. There is no reason to decrypt it again if you already have the plaintext.
    fn try_causal_decrypt<'a>(
        &'a self,
        to_decrypt: &'a mut Vec<(Arc<EncryptedContent<T, Cr>>, SymmetricKey)>,
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        Cr: for<'de> Deserialize<'de>,
        T: Clone + Serialize + for<'de> Deserialize<'de>;
}

#[future_form(
    Sendable where
        S: Send + Sync,
        Cr: Send + Sync,
        T: Send + Sync,
        S::GetCiphertextError: Send,
        S::MarkDecryptedError: Send,
    Local
)]
impl<F: FutureForm, Cr: ContentRef, T, S: CiphertextStore<F, Cr, T>> CiphertextStoreExt<F, Cr, T>
    for S
{
    fn try_causal_decrypt<'a>(
        &'a self,
        to_decrypt: &'a mut Vec<(Arc<EncryptedContent<T, Cr>>, SymmetricKey)>,
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        Cr: for<'de> Deserialize<'de>,
        T: Clone + Serialize + for<'de> Deserialize<'de>,
    {
        F::from_future(async move {
            let mut progress = CausalDecryptionState::new();
            let mut cannot: HashMap<Cr, ErrorReason<F, Cr, T, Self>> = HashMap::new();
            let mut seen = HashSet::new();

            while let Some((ciphertext, key)) = to_decrypt.pop() {
                if !seen.insert(ciphertext.content_ref.clone()) {
                    continue;
                }

                progress.keys.insert(ciphertext.content_ref.clone(), key);
                let content_ref = ciphertext.content_ref.clone();

                match ciphertext.try_decrypt(key) {
                    Err(_) => {
                        seen.remove(&content_ref);
                        cannot.insert(content_ref.clone(), ErrorReason::DecryptionFailed(key));
                        continue;
                    }
                    Ok(decrypted) => {
                        let result: Result<Envelope<Cr, T>, _> =
                            bincode::deserialize(decrypted.as_slice());
                        match result {
                            Err(e) => {
                                seen.remove(&content_ref);
                                cannot.insert(
                                    content_ref.clone(),
                                    ErrorReason::DeserializationFailed(e),
                                );
                                continue;
                            }
                            Ok(envelope) => {
                                for (ancestor_ref, ancestor_key) in envelope.ancestors.iter() {
                                    match self.get_ciphertext(ancestor_ref).await {
                                        Err(e) => {
                                            seen.remove(&content_ref);
                                            cannot.insert(
                                                content_ref.clone(),
                                                ErrorReason::GetCiphertextError(e),
                                            );
                                            continue;
                                        }
                                        Ok(None) => {
                                            progress
                                                .next
                                                .insert(ancestor_ref.clone(), *ancestor_key);
                                        }
                                        Ok(Some(ancestor)) => {
                                            to_decrypt.push((ancestor.dupe(), *ancestor_key));
                                        }
                                    }
                                }

                                progress
                                    .complete
                                    .push((ciphertext.content_ref.clone(), envelope.plaintext));
                            }
                        }
                    }
                }
            }

            for id in progress.complete.iter().map(|(id, _)| id) {
                if let Err(e) = self.mark_decrypted(id).await {
                    cannot.insert(id.clone(), ErrorReason::MarkDecryptedError(e));
                };
            }

            if cannot.is_empty() {
                Ok(progress)
            } else {
                Err(CausalDecryptionError { cannot, progress })
            }
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct CausalDecryptionState<Cr: ContentRef, T> {
    pub complete: Vec<(Cr, T)>,
    pub keys: HashMap<Cr, SymmetricKey>,
    pub next: HashMap<Cr, SymmetricKey>,
}

impl<T, Cr: ContentRef> CausalDecryptionState<Cr, T> {
    pub fn new() -> Self {
        CausalDecryptionState {
            complete: vec![],
            keys: HashMap::new(),
            next: HashMap::new(),
        }
    }
}

#[future_form(Sendable where C: Send + Sync, Cr: Send + Sync, T: Send, Local)]
impl<F: FutureForm, Cr: ContentRef + 'static, T: 'static, C: CiphertextStore<F, Cr, T>>
    CiphertextStore<F, Cr, T> for Arc<Mutex<C>>
where
    C::GetCiphertextError: 'static,
    C::MarkDecryptedError: 'static,
{
    type GetCiphertextError = C::GetCiphertextError;
    type MarkDecryptedError = C::MarkDecryptedError;

    fn get_ciphertext<'a>(
        &'a self,
        cr: &'a Cr,
    ) -> F::Future<'a, Result<Option<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>> {
        F::from_future(async move {
            let locked = self.lock().await;
            locked.get_ciphertext(cr).await
        })
    }

    fn get_ciphertext_by_pcs_update<'a>(
        &'a self,
        pcs_update: &'a Digest<Signed<CgkaOperation>>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>> {
        F::from_future(async move {
            let locked = self.lock().await;
            locked.get_ciphertext_by_pcs_update(pcs_update).await
        })
    }

    fn mark_decrypted<'a>(
        &'a self,
        content_ref: &'a Cr,
    ) -> F::Future<'a, Result<(), Self::MarkDecryptedError>> {
        F::from_future(async move {
            let locked = self.lock().await;
            locked.mark_decrypted(content_ref).await
        })
    }
}

#[future_form(Sendable where Cr: Send + Sync, T: Send + Sync, Local)]
impl<F: FutureForm, T: Clone + 'static, Cr: ContentRef + 'static> CiphertextStore<F, Cr, T>
    for MemoryCiphertextStore<Cr, T>
{
    type GetCiphertextError = Infallible;
    type MarkDecryptedError = Infallible;

    fn get_ciphertext<'a>(
        &'a self,
        cr: &'a Cr,
    ) -> F::Future<'a, Result<Option<Arc<EncryptedContent<T, Cr>>>, Infallible>> {
        F::from_future(async move { Ok(self.get_by_content_ref(cr).await) })
    }

    fn get_ciphertext_by_pcs_update<'a>(
        &'a self,
        pcs_update: &'a Digest<Signed<CgkaOperation>>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Infallible>> {
        F::from_future(async move { Ok(self.get_by_pcs_update(pcs_update).await) })
    }

    fn mark_decrypted<'a>(&'a self, content_ref: &'a Cr) -> F::Future<'a, Result<(), Infallible>> {
        F::from_future(async move {
            self.remove_all(content_ref).await;
            Ok(())
        })
    }
}

pub trait Isomorphic<T> {
    fn pure(inner: T) -> Self;
    fn extract(self) -> T;
}

#[derive(Debug, Error)]
pub struct CausalDecryptionError<F: FutureForm, Cr: ContentRef, T, S: CiphertextStore<F, Cr, T>> {
    pub cannot: HashMap<Cr, ErrorReason<F, Cr, T, S>>,
    pub progress: CausalDecryptionState<Cr, T>,
}

impl<F: FutureForm, Cr: ContentRef + Debug, T: Debug, S: CiphertextStore<F, Cr, T>> Display
    for CausalDecryptionError<F, Cr, T, S>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let x = self.cannot.iter().collect::<Vec<_>>();
        write!(f, "CausalDecryptionError({:?})", x)
    }
}

#[derive(Error)]
#[derive_where(Debug)]
pub enum ErrorReason<F: FutureForm, Cr: ContentRef, T, S: CiphertextStore<F, Cr, T>> {
    #[error("GetCiphertextError: {0}")]
    GetCiphertextError(S::GetCiphertextError),

    #[error("MarkDecryptedError: {0}")]
    MarkDecryptedError(S::MarkDecryptedError),

    #[error(transparent)]
    DeserializationFailed(#[from] bincode::Error),

    #[error("Decryption failed")]
    DecryptionFailed(SymmetricKey),

    #[error("Cannot find ciphertext for ref")]
    CannotFindCiphertext(Cr),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{digest::Digest, envelope::Envelope},
        principal::document::id::DocumentId,
    };
    use beekem::{operation::CgkaOperation, pcs_key::PcsKey};
    use keyhive_crypto::{share_key::ShareSecretKey, signed::Signed, siv::Siv};
    use rand::rngs::OsRng;
    use std::marker::PhantomData;
    use testresult::TestResult;

    // Helper to disambiguate CiphertextStore form
    async fn get_ct<Cr: ContentRef + Send + Sync + 'static, T: Clone + Send + Sync + 'static>(
        store: &MemoryCiphertextStore<Cr, T>,
        id: &Cr,
    ) -> Result<Option<Arc<EncryptedContent<T, Cr>>>, Infallible> {
        CiphertextStore::<Sendable, Cr, T>::get_ciphertext(store, id).await
    }

    fn setup(
        plaintext: String,
        cref: [u8; 32],
        pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
        ancestors: HashMap<[u8; 32], SymmetricKey>,
        doc_id: DocumentId,
        csprng: &mut OsRng,
    ) -> (Arc<EncryptedContent<String, [u8; 32]>>, SymmetricKey) {
        let pcs_key: PcsKey = ShareSecretKey::generate(csprng).into();
        let pcs_key_hash = Digest::hash(&pcs_key);

        let key = SymmetricKey::generate(csprng);
        let envelope = Envelope {
            plaintext,
            ancestors,
        };
        let mut bytes = bincode::serialize(&envelope).unwrap();
        let nonce = Siv::new(&key, bytes.as_slice(), doc_id.as_bytes());
        key.try_encrypt(nonce, &mut bytes).unwrap();

        (
            Arc::new(EncryptedContent::<String, [u8; 32]>::new(
                nonce,
                bytes,
                //
                pcs_key_hash,
                pcs_update_op_hash,
                //
                cref,
                Digest::hash(&vec![]),
            )),
            key,
        )
    }

    #[tokio::test]
    async fn test_hash_map_get_ciphertext() -> TestResult {
        test_utils::init_logging();

        let mut csprng = OsRng;
        let doc_id = DocumentId::generate(&mut csprng);
        let pcs_update_op_hash: Digest<Signed<CgkaOperation>> = Digest {
            raw: blake3::hash(b"PcsOp"),
            _phantom: PhantomData,
        };

        let one_ref = [0u8; 32];
        let two_ref = [1u8; 32];

        let (one, one_key) = setup(
            "one".to_string(),
            one_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (two, _two_key) = setup(
            "two".to_string(),
            two_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(one_ref, one_key)]),
            doc_id,
            &mut csprng,
        );

        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(one.dupe()).await;
        store.insert(two.dupe()).await;

        assert_eq!(get_ct(&store, &one_ref).await, Ok(Some(one)));
        assert_eq!(get_ct(&store, &two_ref).await, Ok(Some(two)));

        Ok(())
    }

    #[tokio::test]
    async fn test_try_causal_decrypt() -> TestResult {
        test_utils::init_logging();

        let mut csprng = OsRng;
        let doc_id = DocumentId::generate(&mut csprng);
        let pcs_update_op_hash: Digest<Signed<CgkaOperation>> = Digest {
            raw: blake3::hash(b"PcsOp"),
            _phantom: PhantomData,
        };

        let genesis_ref = [0u8; 32];
        let left_ref = [1u8; 32];
        let right_ref = [2u8; 32];
        let head_ref = [3u8; 32];

        let (genesis, genesis_key) = setup(
            "genesis".to_string(),
            genesis_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (left, left_key) = setup(
            "left".to_string(),
            left_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis_ref, genesis_key)]),
            doc_id,
            &mut csprng,
        );

        let (right, right_key) = setup(
            "right".to_string(),
            right_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis_ref, genesis_key)]),
            doc_id,
            &mut csprng,
        );

        let (head, head_key) = setup(
            "head".to_string(),
            head_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(left_ref, left_key), (right_ref, right_key)]),
            doc_id,
            &mut csprng,
        );

        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(genesis.clone()).await;
        store.insert(left.clone()).await;
        store.insert(right.clone()).await;
        store.insert(head.clone()).await;

        let observed = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt(
            &store,
            &mut vec![(head.clone(), head_key)],
        )
        .await?;

        assert_eq!(observed.complete.len(), 4);
        assert!(observed
            .complete
            .contains(&(genesis_ref, "genesis".to_string())),);
        assert!(observed.complete.contains(&(left_ref, "left".to_string())),);
        assert!(observed
            .complete
            .contains(&(right_ref, "right".to_string())),);
        assert!(observed.complete.contains(&(head_ref, "head".to_string())),);

        Ok(())
    }

    #[tokio::test]
    async fn test_try_causal_decrypt_multiple_heads() -> TestResult {
        test_utils::init_logging();

        let mut csprng = OsRng;
        let doc_id = DocumentId::generate(&mut csprng);
        let pcs_update_op_hash: Digest<Signed<CgkaOperation>> = Digest {
            raw: blake3::hash(b"PcsOp"),
            _phantom: PhantomData,
        };

        let genesis1_ref = [0u8; 32];
        let genesis2_ref = [1u8; 32];

        let left_ref = [2u8; 32];
        let right_ref = [3u8; 32];

        let head1_ref = [4u8; 32];
        let head2_ref = [5u8; 32];
        let head3_ref = [6u8; 32];

        let (genesis1, genesis1_key) = setup(
            "genesis1".to_string(),
            genesis1_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (genesis2, genesis2_key) = setup(
            "genesis2".to_string(),
            genesis2_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (left, left_key) = setup(
            "left".to_string(),
            left_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis1_ref, genesis1_key)]),
            doc_id,
            &mut csprng,
        );

        let (right, right_key) = setup(
            "right".to_string(),
            right_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis2_ref, genesis2_key), (genesis1_ref, genesis1_key)]),
            doc_id,
            &mut csprng,
        );

        let (head1, _head1_key) = setup(
            "head1".to_string(),
            head1_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(left_ref, left_key), (right_ref, right_key)]),
            doc_id,
            &mut csprng,
        );

        let (head2, head2_key) = setup(
            "head2".to_string(),
            head2_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(left_ref, left_key)]),
            doc_id,
            &mut csprng,
        );

        let (head3, head3_key) = setup(
            "head3".to_string(),
            head3_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(right_ref, right_key)]),
            doc_id,
            &mut csprng,
        );

        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(genesis1.clone()).await;
        store.insert(genesis2.clone()).await;
        store.insert(left.clone()).await;
        store.insert(right.clone()).await;
        store.insert(head1.clone()).await;
        store.insert(head2.clone()).await;
        store.insert(head3.clone()).await;

        let observed = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt(
            &store,
            &mut vec![(head2.clone(), head2_key), (head3.clone(), head3_key)],
        )
        .await?;

        // Doesn't have the unused head
        assert!(!observed
            .complete
            .contains(&(head1_ref, "head1".to_string())));

        assert!(observed
            .complete
            .contains(&(head2_ref, "head2".to_string())));
        assert!(observed
            .complete
            .contains(&(head3_ref, "head3".to_string())));

        assert!(observed.complete.contains(&(left_ref, "left".to_string())),);
        assert!(observed
            .complete
            .contains(&(right_ref, "right".to_string())));

        assert!(observed
            .complete
            .contains(&(genesis1_ref, "genesis1".to_string())),);
        assert!(observed
            .complete
            .contains(&(genesis2_ref, "genesis2".to_string())),);

        assert_eq!(observed.complete.len(), 6);
        assert_eq!(observed.next.len(), 0);

        assert_eq!(observed.keys.len(), 6);
        assert_eq!(observed.keys.get(&head2_ref), Some(&head2_key));
        assert_eq!(observed.keys.get(&head3_ref), Some(&head3_key));
        assert_eq!(observed.keys.get(&left_ref), Some(&left_key));
        assert_eq!(observed.keys.get(&right_ref), Some(&right_key));
        assert_eq!(observed.keys.get(&genesis1_ref), Some(&genesis1_key));
        assert_eq!(observed.keys.get(&genesis2_ref), Some(&genesis2_key));

        Ok(())
    }

    #[tokio::test]
    async fn test_incomplete_store() -> TestResult {
        test_utils::init_logging();

        let mut csprng = OsRng;
        let doc_id = DocumentId::generate(&mut OsRng);
        let pcs_update_op_hash: Digest<Signed<CgkaOperation>> = Digest {
            raw: blake3::hash(b"PcsOp"),
            _phantom: PhantomData,
        };

        let genesis1_ref = [0u8; 32];
        let genesis2_ref = [1u8; 32];

        let left_ref = [2u8; 32];
        let right_ref = [3u8; 32];

        let head1_ref = [4u8; 32];
        let head2_ref = [5u8; 32];
        let head3_ref = [6u8; 32];

        let (_genesis1, genesis1_key) = setup(
            "genesis1".to_string(),
            genesis1_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (_genesis2, genesis2_key) = setup(
            "genesis2".to_string(),
            genesis2_ref,
            pcs_update_op_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (left, left_key) = setup(
            "left".to_string(),
            left_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis1_ref, genesis1_key)]),
            doc_id,
            &mut csprng,
        );

        let (right, right_key) = setup(
            "right".to_string(),
            right_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(genesis2_ref, genesis2_key), (genesis1_ref, genesis1_key)]),
            doc_id,
            &mut csprng,
        );

        let (head1, _head1_key) = setup(
            "head1".to_string(),
            head1_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(left_ref, left_key), (right_ref, right_key)]),
            doc_id,
            &mut csprng,
        );

        let (head2, head2_key) = setup(
            "head2".to_string(),
            head2_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(left_ref, left_key)]),
            doc_id,
            &mut csprng,
        );

        let (head3, head3_key) = setup(
            "head3".to_string(),
            head3_ref,
            pcs_update_op_hash,
            HashMap::from_iter([(right_ref, right_key)]),
            doc_id,
            &mut csprng,
        );

        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        // NOTE: skipping: (genesis1_ref, genesis1.clone()),
        // NOTE: skipping (genesis2_ref, genesis2.clone()),
        store.insert(left.clone()).await;
        store.insert(right.clone()).await;
        store.insert(head1.clone()).await;
        store.insert(head2.clone()).await;
        store.insert(head3.clone()).await;

        let observed = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt(
            &store,
            &mut vec![(head2.clone(), head2_key), (head3.clone(), head3_key)],
        )
        .await?;

        // Doesn't have the unused head
        assert!(!observed
            .complete
            .contains(&(head1_ref, "head1".to_string())));

        assert!(observed
            .complete
            .contains(&(head2_ref, "head2".to_string())));
        assert!(observed
            .complete
            .contains(&(head3_ref, "head3".to_string())));

        assert!(observed.complete.contains(&(left_ref, "left".to_string())),);
        assert!(observed
            .complete
            .contains(&(right_ref, "right".to_string())));

        assert!(!observed
            .complete
            .contains(&(genesis1_ref, "genesis1".to_string())),);
        assert!(!observed
            .complete
            .contains(&(genesis2_ref, "genesis2".to_string())),);

        assert_eq!(observed.complete.len(), 4);

        assert_eq!(observed.keys.len(), 4);
        assert_eq!(observed.keys.get(&head2_ref), Some(&head2_key));
        assert_eq!(observed.keys.get(&head3_ref), Some(&head3_key));
        assert_eq!(observed.keys.get(&left_ref), Some(&left_key));
        assert_eq!(observed.keys.get(&right_ref), Some(&right_key));

        assert_eq!(observed.next.len(), 2);
        assert_eq!(observed.next.get(&genesis1_ref), Some(&genesis1_key));
        assert_eq!(observed.next.get(&genesis2_ref), Some(&genesis2_key));

        Ok(())
    }
}
