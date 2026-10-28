//! A store for encrypted content plus some metadata.

pub mod memory;

use self::memory::MemoryCiphertextStore;
use crate::{
    ancestor_key::AncestorKey,
    application_secret::GroupSecretOrigin,
    encrypted::EncryptedContent,
    envelope::{Envelope, OpenEnvelopeError},
    reference::ContentRef,
};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, identifier::Identifier, symmetric_key::SymmetricKey};
use std::{
    boxed::Box,
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    fmt::{Debug, Display},
    sync::Arc,
    vec,
    vec::Vec,
};
use thiserror::Error;

/// An async storage interface for ciphertexts.
///
/// The `F: FutureForm` parameter determines whether the returned
/// futures are `Send` ([`Sendable`]) or
/// `!Send` ([`Local`]).
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

    fn get_ciphertext_by_group_secret_origin<'a>(
        &'a self,
        origin: &'a Digest<GroupSecretOrigin>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>>;

    fn mark_decrypted<'a>(
        &'a self,
        id: &'a Cr,
    ) -> F::Future<'a, Result<(), Self::MarkDecryptedError>>;
}

/// Extension trait providing [`try_causal_decrypt`] and
/// [`try_causal_decrypt_from_keys`] for all [`CiphertextStore`]
/// implementations.
///
/// This is a separate trait because the default method body uses
/// `F::from_future(async { ... })` which requires concrete `F`
/// (either [`Sendable`] or [`Local`]). The `#[future_form]` macro
/// stamps out both variants via a blanket impl.
///
/// Neither method stores the keys it finds. They are in the returned state's
/// [`keys`][CausalDecryptionState::keys]. A caller that will later write
/// content referring to these blocks as predecessors has to store them itself.
///
/// [`try_causal_decrypt`]: CiphertextStoreExt::try_causal_decrypt
/// [`try_causal_decrypt_from_keys`]: CiphertextStoreExt::try_causal_decrypt_from_keys
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
    ///     subgraph head[Read Capability]
    ///       pointer_head["Pointer #️⃣"]
    ///       key_head["Key 🔑"]
    ///     end
    ///
    ///     pointer_head --> block3
    /// ```
    ///
    /// By passing in the entrypoint, further keys are discovered, and can be pulled out
    /// the store, which contain more keys and references, and so on.
    ///
    /// It is normal for this to stop decryption if it encounters an already-decrypted
    /// ciphertext. There is no reason to decrypt it again if you already have the plaintext.
    fn try_causal_decrypt<'a>(
        &'a self,
        doc_id: Identifier,
        to_decrypt: &'a mut Vec<(Arc<EncryptedContent<T, Cr>>, SymmetricKey)>,
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        T: Clone + Encode + Decode;

    /// Causally decrypts content whose keys are already known (either the
    /// ancestors an opened [`Envelope`] lists or the
    /// [`next`][CausalDecryptionState::next] of an earlier decryption).
    ///
    /// Everything in `start` is fetched from this store and decrypted with its
    /// key, then the traversal continues as in
    /// [`try_causal_decrypt`][CiphertextStoreExt::try_causal_decrypt].
    /// Anything in `start` the store does not contain is placed in the returned
    /// state's [`next`][CausalDecryptionState::next], with its key, so a later
    /// call can start from it.
    ///
    /// If any block cannot be fetched, decrypted or marked decrypted, or its
    /// body is not an envelope whose payload decodes as `T`, returns [`CausalDecryptionError`] with
    /// the reason in its [`cannot`][CausalDecryptionError::cannot] and the
    /// state in its [`progress`][CausalDecryptionError::progress]. A failure
    /// to fetch an ancestor of `start` is listed under the block that listed
    /// it, and that ancestor's key is not kept.
    fn try_causal_decrypt_from_keys<'a>(
        &'a self,
        doc_id: Identifier,
        start: &'a [(Cr, SymmetricKey)],
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        T: Clone + Encode + Decode + 'a;
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
        doc_id: Identifier,
        to_decrypt: &'a mut Vec<(Arc<EncryptedContent<T, Cr>>, SymmetricKey)>,
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        T: Clone + Encode + Decode,
    {
        F::from_future(async move {
            let mut progress = CausalDecryptionState::new();
            let mut cannot: HashMap<Cr, ErrorReason<F, Cr, T, Self>> = HashMap::new();
            let mut seen = HashSet::new();

            while let Some((ciphertext, key)) = to_decrypt.pop() {
                if !seen.insert(ciphertext.content_ref.clone()) {
                    continue;
                }

                let content_ref = ciphertext.content_ref.clone();

                let opened = match Envelope::<Cr, Vec<u8>>::open(&ciphertext, key, doc_id) {
                    Ok((envelope, opened_by)) => T::decode(&envelope.plaintext)
                        .map(|plaintext| (plaintext, envelope.ancestors, opened_by))
                        .map_err(ErrorReason::DeserializationFailed),
                    Err(OpenEnvelopeError::Decrypt(_)) => Err(ErrorReason::DecryptionFailed(key)),
                    Err(OpenEnvelopeError::Decode(e)) => Err(ErrorReason::DeserializationFailed(e)),
                };
                let (plaintext, ancestors, opened_by) = match opened {
                    Ok(opened) => opened,
                    Err(reason) => {
                        seen.remove(&content_ref);
                        cannot.insert(content_ref, reason);
                        continue;
                    }
                };
                for (ancestor_ref, ancestor_key) in ancestors {
                    match self.get_ciphertext(&ancestor_ref).await {
                        Err(e) => {
                            seen.remove(&content_ref);
                            cannot.insert(content_ref.clone(), ErrorReason::GetCiphertextError(e));
                            continue;
                        }
                        Ok(None) => {
                            progress.next.insert(ancestor_ref, ancestor_key);
                        }
                        Ok(Some(ancestor)) => {
                            to_decrypt.push((ancestor.dupe(), ancestor_key));
                        }
                    }
                }

                progress.keys.insert(content_ref.clone(), opened_by);
                progress.complete.push((content_ref, plaintext));
            }

            for id in progress.complete.iter().map(|(id, _)| id) {
                if let Err(e) = self.mark_decrypted(id).await {
                    cannot.insert(id.clone(), ErrorReason::MarkDecryptedError(e));
                };
            }

            if cannot.is_empty() {
                Ok(progress)
            } else {
                Err(CausalDecryptionError {
                    cannot,
                    progress: Box::new(progress),
                })
            }
        })
    }

    fn try_causal_decrypt_from_keys<'a>(
        &'a self,
        doc_id: Identifier,
        start: &'a [(Cr, SymmetricKey)],
    ) -> F::Future<'a, Result<CausalDecryptionState<Cr, T>, CausalDecryptionError<F, Cr, T, Self>>>
    where
        T: Clone + Encode + Decode + 'a,
    {
        F::from_future(async move {
            let mut to_decrypt = vec![];
            let mut not_served = HashMap::new();
            let mut cannot = HashMap::new();
            for (content_ref, key) in start {
                match self.get_ciphertext(content_ref).await {
                    Ok(Some(encrypted)) => to_decrypt.push((encrypted, *key)),
                    Ok(None) => {
                        not_served.insert(content_ref.clone(), *key);
                    }
                    Err(e) => {
                        cannot.insert(content_ref.clone(), ErrorReason::GetCiphertextError(e));
                    }
                }
            }

            let (mut progress, causal_decrypt_cannot) =
                match self.try_causal_decrypt(doc_id, &mut to_decrypt).await {
                    Ok(progress) => (progress, HashMap::new()),
                    Err(err) => (*err.progress, err.cannot),
                };
            progress.next.extend(not_served);
            cannot.extend(causal_decrypt_cannot);
            if cannot.is_empty() {
                Ok(progress)
            } else {
                Err(CausalDecryptionError {
                    cannot,
                    progress: Box::new(progress),
                })
            }
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct CausalDecryptionState<Cr: ContentRef, T> {
    /// Each block read, with its payload.
    pub complete: Vec<(Cr, T)>,

    /// The key that opened each block in `complete`.
    pub keys: HashMap<Cr, AncestorKey<Cr>>,

    /// Blocks the store did not have, each with the key an envelope listed
    /// for it, which has not been checked.
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

    fn get_ciphertext_by_group_secret_origin<'a>(
        &'a self,
        origin: &'a Digest<GroupSecretOrigin>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Self::GetCiphertextError>> {
        F::from_future(async move {
            let locked = self.lock().await;
            locked.get_ciphertext_by_group_secret_origin(origin).await
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

    fn get_ciphertext_by_group_secret_origin<'a>(
        &'a self,
        origin: &'a Digest<GroupSecretOrigin>,
    ) -> F::Future<'a, Result<Vec<Arc<EncryptedContent<T, Cr>>>, Infallible>> {
        F::from_future(async move { Ok(self.get_by_group_secret_origin(origin).await) })
    }

    fn mark_decrypted<'a>(&'a self, content_ref: &'a Cr) -> F::Future<'a, Result<(), Infallible>> {
        F::from_future(async move {
            self.remove_all(content_ref).await;
            Ok(())
        })
    }
}

#[derive(Debug, Error)]
pub struct CausalDecryptionError<F: FutureForm, Cr: ContentRef, T, S: CiphertextStore<F, Cr, T>> {
    pub cannot: HashMap<Cr, ErrorReason<F, Cr, T, S>>,
    /// Boxed because `CausalDecryptionState` contains three collections,
    /// which would make the error large.
    pub progress: Box<CausalDecryptionState<Cr, T>>,
}

impl<F: FutureForm, Cr: ContentRef + Debug, T: Debug, S: CiphertextStore<F, Cr, T>> Display
    for CausalDecryptionError<F, Cr, T, S>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    DeserializationFailed(#[from] DecodeError),

    #[error("Decryption failed")]
    DecryptionFailed(SymmetricKey),

    #[error("Cannot find ciphertext for ref")]
    CannotFindCiphertext(Cr),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application_secret::GroupSecret, encrypted::PredecessorRefs};
    use ed25519_dalek::SigningKey;
    use keyhive_crypto::share_key::ShareSecretKey;
    use rand::rngs::OsRng;
    use std::{
        marker::PhantomData,
        string::{String, ToString},
    };
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
        group_secret_origin_hash: Digest<GroupSecretOrigin>,
        ancestors: HashMap<[u8; 32], SymmetricKey>,
        doc_id: Identifier,
        csprng: &mut OsRng,
    ) -> (Arc<EncryptedContent<String, [u8; 32]>>, SymmetricKey) {
        let group_secret: GroupSecret = ShareSecretKey::generate(csprng).into();
        let group_secret_hash = group_secret.digest();

        let key = SymmetricKey::generate(csprng);
        let envelope = Envelope {
            plaintext,
            ancestors,
        };
        let bytes = envelope.encode().into_bytes();
        (
            Arc::new(
                EncryptedContent::<String, [u8; 32]>::encrypt(
                    &key,
                    doc_id,
                    cref,
                    PredecessorRefs::digest(&[]),
                    group_secret_hash,
                    group_secret_origin_hash,
                    &bytes,
                )
                .expect("a fresh key encrypts"),
            ),
            key,
        )
    }

    #[tokio::test]
    async fn removing_a_ciphertext_returns_it_and_forgets_it() -> TestResult {
        let mut csprng = OsRng;
        let doc_id = Identifier::from(&SigningKey::generate(&mut csprng));
        let origin: Digest<GroupSecretOrigin> = [9u8; 32].into();
        let (one, _) = setup(
            "one".to_string(),
            [0; 32],
            origin,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );
        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(one.dupe()).await;
        assert_eq!(
            store.get_by_group_secret_origin(&origin).await,
            vec![one.dupe()]
        );

        assert_eq!(store.remove(&one.digest()).await, Some(one));
        assert_eq!(get_ct(&store, &[0; 32]).await, Ok(None));
        assert!(store.get_by_group_secret_origin(&origin).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_hash_map_get_ciphertext() -> TestResult {
        test_utils::init_logging();

        let mut csprng = OsRng;
        let doc_id = Identifier::from(&SigningKey::generate(&mut csprng));
        let group_secret_origin_hash: Digest<GroupSecretOrigin> = Digest {
            raw: blake3::hash(b"PcsOp"),
            _phantom: PhantomData,
        };

        let one_ref = [0u8; 32];
        let two_ref = [1u8; 32];

        let (one, one_key) = setup(
            "one".to_string(),
            one_ref,
            group_secret_origin_hash,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );

        let (two, _two_key) = setup(
            "two".to_string(),
            two_ref,
            group_secret_origin_hash,
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

    /// An envelope that contains the wrong key for an ancestor does not open it.
    /// Decryption reports the ancestor instead of trusting the key.
    #[tokio::test]
    async fn a_wrong_ancestor_key_in_an_envelope_does_not_decrypt_the_ancestor() -> TestResult {
        let mut csprng = OsRng;
        let doc_id = Identifier::from(&SigningKey::generate(&mut csprng));
        let origin: Digest<GroupSecretOrigin> = [9u8; 32].into();
        let (one_ref, two_ref) = ([0u8; 32], [1u8; 32]);
        let wrong_key = SymmetricKey::generate(&mut csprng);

        let (one, _one_key) = setup(
            "one".to_string(),
            one_ref,
            origin,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );
        let (two, two_key) = setup(
            "two".to_string(),
            two_ref,
            origin,
            HashMap::from_iter([(one_ref, wrong_key)]),
            doc_id,
            &mut csprng,
        );
        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(one).await;
        store.insert(two.dupe()).await;

        let mut to_decrypt = vec![(two, two_key)];
        let Err(err) = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt(
            &store,
            doc_id,
            &mut to_decrypt,
        )
        .await
        else {
            panic!("the ancestor decrypted under the wrong key");
        };
        assert!(matches!(
            err.cannot.get(&one_ref),
            Some(ErrorReason::DecryptionFailed(key)) if *key == wrong_key
        ));
        assert_eq!(err.progress.complete, vec![(two_ref, "two".to_string())]);
        Ok(())
    }

    #[tokio::test]
    async fn a_causal_decrypt_from_known_keys_reads_each_start_or_reports_why_not() -> TestResult {
        let mut csprng = OsRng;
        let doc_id = Identifier::from(&SigningKey::generate(&mut csprng));
        let origin: Digest<GroupSecretOrigin> = [9u8; 32].into();
        let (parent_ref, read_ref, absent_ref, refused_ref) =
            ([0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
        let (parent_key, absent_key, wrong_key) = (
            SymmetricKey::generate(&mut csprng),
            SymmetricKey::generate(&mut csprng),
            SymmetricKey::generate(&mut csprng),
        );
        let (read, read_key) = setup(
            "read".to_string(),
            read_ref,
            origin,
            HashMap::from_iter([(parent_ref, parent_key)]),
            doc_id,
            &mut csprng,
        );
        let (refused, _) = setup(
            "refused".to_string(),
            refused_ref,
            origin,
            HashMap::new(),
            doc_id,
            &mut csprng,
        );
        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(read).await;
        store.insert(refused).await;

        let start = [
            (read_ref, read_key),
            (absent_ref, absent_key),
            (refused_ref, wrong_key),
        ];
        let Err(err) = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt_from_keys(
            &store, doc_id, &start,
        )
        .await
        else {
            panic!("the block under the wrong key decrypted");
        };
        assert_eq!(err.progress.complete, vec![(read_ref, "read".to_string())]);
        assert_eq!(
            err.progress.next,
            HashMap::from_iter([(parent_ref, parent_key), (absent_ref, absent_key)])
        );
        assert!(matches!(
            err.cannot.get(&refused_ref),
            Some(ErrorReason::DecryptionFailed(key)) if *key == wrong_key
        ));
        assert_eq!(err.cannot.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_causal_decrypt_from_known_keys_that_reads_every_start_is_ok() -> TestResult {
        let mut csprng = OsRng;
        let doc_id = Identifier::from(&SigningKey::generate(&mut csprng));
        let (only, only_key) = setup(
            "only".to_string(),
            [0u8; 32],
            [9u8; 32].into(),
            HashMap::new(),
            doc_id,
            &mut csprng,
        );
        let store = MemoryCiphertextStore::<[u8; 32], String>::new();
        store.insert(only).await;

        let read = CiphertextStoreExt::<Sendable, _, _>::try_causal_decrypt_from_keys(
            &store,
            doc_id,
            &[([0u8; 32], only_key)],
        )
        .await
        .expect("every start is read");
        assert_eq!(read.complete, vec![([0u8; 32], "only".to_string())]);
        Ok(())
    }
}
