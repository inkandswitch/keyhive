//! A store for encrypted content plus some metadata.

use crate::{
    content::reference::ContentRef,
    crypto::{encrypted::EncryptedContent, envelope::Envelope, symmetric_key::SymmetricKey},
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
};
use thiserror::Error;

/// An async storage interface for ciphertexts.
///
/// There are `!Send` and `Send` variants of this trait:
/// if you need `Send`, enable the `sendable` feature.
///
/// This includes functionality for "causal decryption":
/// the ability to decrypt a set of causally-related ciphertexts.
/// See [`try_causal_decrypt`][CiphertextStore::try_causal_decrypt] for more information.
///
/// The `get_ciphertext` method generally fails on items that have already been decrypted.
/// This is generally accomplished by either removing the decrypted values from the store,
/// or — more commonly — by tracking which values have been decrypted and simply not
/// hitting the backing store on requests for those IDs.
pub trait CiphertextStore<T, Cr: ContentRef> {
    #[cfg(feature = "sendable")]
    fn get_ciphertext(
        &self,
        id: &Cr,
    ) -> impl Future<Output = Option<EncryptedContent<T, Cr>>> + Send;

    #[cfg(not(feature = "sendable"))]
    fn get_ciphertext(&self, id: &Cr) -> impl Future<Output = Option<EncryptedContent<T, Cr>>>;

    #[cfg_attr(all(doc, feature = "mermaid_docs"), aquamarine::aquamarine)]
    /// Recursively decryptsa set of causally-related ciphertexts.
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
    /// It is normal for this to stop decryption if it enounters an already-decrypted
    /// ciphertext. There is no reason to decrypt it again if you already have the plaintext.
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

            acc.keys.insert(ciphertext.content_ref.clone(), key);
            let content_ref = ciphertext.content_ref.clone();

            let decrypted = ciphertext
                .try_decrypt(key)
                .map_err(|_| CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        content_ref.clone(),
                        ErrorReason::DecryptionFailed(key),
                    )]),
                })?;

            let envelope: Envelope<Cr, T> =
                bincode::deserialize(decrypted.as_slice()).map_err(|e| CausalDecryptionError {
                    progress: acc.clone(),
                    cannot: HashMap::from_iter([(
                        content_ref,
                        ErrorReason::DeserializationFailed(e.into()),
                    )]),
                })?;

            for (ancestor_ref, ancestor_key) in envelope.ancestors.iter() {
                if let Some(ancestor) = self.get_ciphertext(&ancestor_ref).await {
                    to_decrypt.push((ancestor, *ancestor_key));
                } else {
                    acc.next.insert(ancestor_ref.clone(), *ancestor_key);
                }
            }

            acc.complete
                .push((ciphertext.content_ref, envelope.plaintext));
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

#[cfg(not(feature = "sendable"))]
impl<T: Clone, Cr: ContentRef> CiphertextStore<T, Cr> for HashMap<Cr, EncryptedContent<T, Cr>> {
    async fn get_ciphertext(&self, id: &Cr) -> Option<EncryptedContent<T, Cr>> {
        HashMap::get(self, id).cloned()
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
    use crate::{
        cgka::operation::CgkaOperation,
        crypto::{
            application_secret::PcsKey, digest::Digest, envelope::Envelope,
            share_key::ShareSecretKey, signed::Signed, siv::Siv,
        },
        principal::document::id::DocumentId,
    };
    use rand::rngs::ThreadRng;
    use std::marker::PhantomData;

    fn setup(
        plaintext: String,
        cref: [u8; 32],
        pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
        ancestors: HashMap<[u8; 32], SymmetricKey>,
        doc_id: DocumentId,
        csprng: &mut ThreadRng,
    ) -> (EncryptedContent<String, [u8; 32]>, SymmetricKey) {
        let pcs_key: PcsKey = ShareSecretKey::generate(csprng).into();
        let pcs_key_hash = Digest::hash(&pcs_key);

        let key = SymmetricKey::generate(csprng);
        let envelope = Envelope {
            plaintext,
            ancestors,
        };
        let mut bytes = bincode::serialize(&envelope).unwrap();
        let nonce = Siv::new(&key, bytes.as_slice(), doc_id).unwrap();
        key.try_encrypt(nonce, &mut bytes).unwrap();

        (
            EncryptedContent::<String, [u8; 32]>::new(
                nonce,
                bytes,
                //
                pcs_key_hash,
                pcs_update_op_hash,
                //
                cref,
                Digest::hash(&vec![]),
            ),
            key,
        )
    }

    #[tokio::test]
    async fn test_hash_map_get_ciphertext() {
        let mut csprng = rand::thread_rng();
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

        let store = HashMap::<[u8; 32], EncryptedContent<String, [u8; 32]>>::from_iter([
            (one_ref, one.clone()),
            (two_ref, two.clone()),
        ]);

        assert_eq!(store.get_ciphertext(&one_ref).await, Some(one));
        assert_eq!(store.get_ciphertext(&two_ref).await, Some(two));
    }

    #[tokio::test]
    async fn test_try_causal_decrypt() {
        let mut csprng = rand::thread_rng();
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

        let store = HashMap::<[u8; 32], EncryptedContent<String, [u8; 32]>>::from_iter([
            (genesis_ref, genesis.clone()),
            (left_ref, left.clone()),
            (right_ref, right.clone()),
            (head_ref, head.clone()),
        ]);

        let observed = store
            .try_causal_decrypt(&mut vec![(head.clone(), head_key)])
            .await
            .unwrap();

        assert_eq!(observed.complete.len(), 4);
        assert!(observed
            .complete
            .contains(&(genesis_ref, "genesis".to_string())),);
        assert!(observed.complete.contains(&(left_ref, "left".to_string())),);
        assert!(observed
            .complete
            .contains(&(right_ref, "right".to_string())),);
        assert!(observed.complete.contains(&(head_ref, "head".to_string())),);
    }

    #[tokio::test]
    async fn test_try_causal_decrypt_multiple_heads() {
        let mut csprng = rand::thread_rng();
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

        let store = HashMap::<[u8; 32], EncryptedContent<String, [u8; 32]>>::from_iter([
            (genesis1_ref, genesis1.clone()),
            (genesis2_ref, genesis2.clone()),
            (left_ref, left.clone()),
            (right_ref, right.clone()),
            (head1_ref, head1.clone()),
            (head2_ref, head2.clone()),
            (head3_ref, head3.clone()),
        ]);

        let observed = store
            .try_causal_decrypt(&mut vec![
                (head2.clone(), head2_key),
                (head3.clone(), head3_key),
            ])
            .await
            .unwrap();

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
    }

    #[tokio::test]
    async fn test_incomplete_store() {
        let mut csprng = rand::thread_rng();
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

        let store = HashMap::<[u8; 32], EncryptedContent<String, [u8; 32]>>::from_iter([
            // NOTE: skipping: (genesis1_ref, genesis1.clone()),
            // NOTE: skipping (genesis2_ref, genesis2.clone()),
            (left_ref, left.clone()),
            (right_ref, right.clone()),
            (head1_ref, head1.clone()),
            (head2_ref, head2.clone()),
            (head3_ref, head3.clone()),
        ]);

        let observed = store
            .try_causal_decrypt(&mut vec![
                (head2.clone(), head2_key),
                (head3.clone(), head3_key),
            ])
            .await
            .unwrap();

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
    }
}
