//! Causal encryption: content that contains its ancestors' keys, in their own section,
//! and decryption that traverses back through them over the application's own
//! storage.

use super::{
    ancestor::{JsAncestor, JsAncestorRef},
    change_id::JsChangeId,
    document_id::JsDocumentId,
    encrypted::JsEncrypted,
    encrypted_keyed::JsEncryptedKeyed,
    keyhive::{JsDecryptError, JsEncryptError, JsKeyhive},
};
use crate::macros::init_span;
use from_js_ref::FromJsRef;
use future_form::{FutureForm, Local};
use keyhive_codec::traits::Decode;
use keyhive_content::{
    application_secret::GroupSecretOrigin,
    encrypted::EncryptedContent,
    store::{CausalDecryptionState, CiphertextStore, CiphertextStoreExt},
};
use keyhive_crypto::{digest::Digest, symmetric_key::SymmetricKey};
use std::{cell::RefCell, convert::Infallible, rc::Rc, sync::Arc};
use thiserror::Error;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(js_class = Keyhive)]
impl JsKeyhive {
    /// Encrypt `content` with the keys of its `ancestors`, so a reader
    /// who opens it can open them too. The ancestors are also the content's
    /// predecessors, in any order. Read it back with `tryCausalDecrypt`.
    ///
    /// Returns the content with its own key, for a later write to contain.
    #[wasm_bindgen(js_name = tryEncryptWithAncestors)]
    pub async fn try_encrypt_with_ancestors(
        &self,
        doc_id: &JsDocumentId,
        content_ref: &JsChangeId,
        ancestors: Vec<JsAncestorRef>,
        content: &[u8],
    ) -> Result<JsEncryptedKeyed, JsEncryptError> {
        init_span!("JsKeyhive::try_encrypt_with_ancestors");
        let ancestors: Vec<_> = ancestors
            .iter()
            .map(|r| JsAncestor::from_js_ref(r).into_parts())
            .collect();
        let (inner, key) = self
            .0
            .try_encrypt_content_with_ancestors(doc_id.0, content_ref, &ancestors, content)
            .await?;
        Ok(JsEncryptedKeyed {
            inner,
            application_secret: key.as_slice().to_vec(),
        })
    }

    /// Decrypt `encrypted`, written by `tryEncryptWithAncestors`, with this
    /// keyhive's key for it, then the ancestors it lists, and theirs
    /// in turn, as `tryCausalDecryptFrom` does. `encrypted` is the first block
    /// in `complete()`.
    ///
    /// Throws a `DecryptError` if this keyhive cannot decrypt `encrypted` and
    /// an `Error` if its ancestors section does not decrypt or is malformed.
    /// Failures among its ancestors are reported in `failed()`, not thrown.
    #[wasm_bindgen(js_name = tryCausalDecrypt)]
    pub async fn try_causal_decrypt(
        &self,
        doc_id: &JsDocumentId,
        encrypted: &JsEncrypted,
        load: js_sys::Function,
    ) -> Result<JsCausalDecryption, JsValue> {
        init_span!("JsKeyhive::try_causal_decrypt");
        let (plaintext, key) = self
            .0
            .try_decrypt_content_keyed(doc_id.0, &encrypted.0)
            .await
            .map_err(JsDecryptError::from)?;
        let start = encrypted
            .0
            .try_decrypt_ancestors(key, doc_id.0.into())
            .map_err(|e| JsError::new(&format!("the ancestors do not decrypt: {e}")))?;
        let mut decryption = causal_decrypt(doc_id, &start, load).await;
        decryption.complete.insert(
            0,
            JsDecryptedContent {
                content_ref: encrypted.0.content_ref.clone(),
                content: plaintext.into(),
                key,
            },
        );
        Ok(decryption)
    }

    /// Decrypt each of `start` with its key, then the ancestors each lists,
    /// and theirs in turn. `start` is the ancestors of a block already
    /// read, a block's own `ChangeId` and key, or the `next()` of an earlier
    /// decryption.
    ///
    /// `load` is called with a `ChangeId` and returns that block's bytes
    /// (`Encrypted.toBytes()`), a promise of them, or `undefined` or `null` if
    /// the application does not have it. A block it does not have is reported
    /// in `next()`, so returning `undefined` for content already read stops the
    /// traversal there. If `load` throws, rejects, returns anything else, or
    /// returns bytes that are not this block's encrypted content, the block is
    /// reported in both `next()` and `failed()`. `load` is called once for each
    /// listing of a block, so a block that several blocks list can be loaded
    /// more than once. This never throws.
    #[wasm_bindgen(js_name = tryCausalDecryptFrom)]
    pub async fn try_causal_decrypt_from(
        &self,
        doc_id: &JsDocumentId,
        start: Vec<JsAncestorRef>,
        load: js_sys::Function,
    ) -> JsCausalDecryption {
        init_span!("JsKeyhive::try_causal_decrypt_from");
        let start: Vec<_> = start
            .iter()
            .map(|r| JsAncestor::from_js_ref(r).into_parts())
            .collect();
        causal_decrypt(doc_id, &start, load).await
    }
}

async fn causal_decrypt(
    doc_id: &JsDocumentId,
    start: &[(JsChangeId, SymmetricKey)],
    load: js_sys::Function,
) -> JsCausalDecryption {
    let store = JsLoadStore {
        load,
        failed: RefCell::default(),
    };
    let walked = CiphertextStoreExt::<Local, _, _>::try_causal_decrypt_from_keys(
        &store,
        doc_id.0.into(),
        start,
    )
    .await;
    let (state, cannot) = match walked {
        Ok(state) => (state, Default::default()),
        Err(err) => (*err.progress, err.cannot),
    };
    let CausalDecryptionState {
        complete,
        keys,
        next,
    } = state;
    let not_loaded = store
        .failed
        .into_inner()
        .into_iter()
        .map(|(content_ref, reason)| (content_ref, reason.to_string()));
    let not_opened = cannot
        .into_iter()
        .map(|(content_ref, reason)| (content_ref, reason.to_string()));
    JsCausalDecryption {
        complete: complete
            .into_iter()
            .map(|(content_ref, content)| JsDecryptedContent {
                key: *keys
                    .get(&content_ref)
                    .expect("the traversal records the key of each block it reads"),
                content_ref,
                content: content.into(),
            })
            .collect(),
        next: next
            .into_iter()
            .map(|(content_ref, key)| JsAncestor { content_ref, key })
            .collect(),
        failed: not_loaded
            .chain(not_opened)
            .map(|(content_ref, reason)| JsDecryptFailure {
                content_ref,
                reason,
            })
            .collect(),
    }
}

/// What a causal decryption read, what it did not reach, and what it could
/// not read.
#[wasm_bindgen(js_name = CausalDecryption)]
#[derive(Debug)]
pub struct JsCausalDecryption {
    complete: Vec<JsDecryptedContent>,
    next: Vec<JsAncestor>,
    failed: Vec<JsDecryptFailure>,
}

#[wasm_bindgen(js_class = CausalDecryption)]
impl JsCausalDecryption {
    /// Each block read. Their order is not causal.
    pub fn complete(&self) -> Vec<JsDecryptedContent> {
        self.complete.clone()
    }

    /// Blocks `load` did not provide, each with the key that opens it.
    pub fn next(&self) -> Vec<JsAncestor> {
        self.next.clone()
    }

    /// Blocks that could not be read, because `load` failed for the block, the
    /// key it was provided does not open it, or its ancestors section or
    /// content is malformed. A block `load` failed for is also in `next()` to
    /// retry. A block can be listed more than once, and can also be in
    /// `complete()`: if it was provided two keys and one was wrong, or if
    /// `load` failed for it once and gave it another time.
    pub fn failed(&self) -> Vec<JsDecryptFailure> {
        self.failed.clone()
    }
}

/// One block a causal decryption read.
#[wasm_bindgen(js_name = DecryptedContent)]
#[derive(Debug, Clone)]
pub struct JsDecryptedContent {
    content_ref: JsChangeId,
    content: Rc<[u8]>,
    key: SymmetricKey,
}

#[wasm_bindgen(js_class = DecryptedContent)]
impl JsDecryptedContent {
    /// The block's `ChangeId`.
    #[wasm_bindgen(getter, js_name = contentRef)]
    pub fn content_ref(&self) -> JsChangeId {
        self.content_ref.clone()
    }

    /// Copies the content out of wasm memory on every call.
    pub fn content(&self) -> Vec<u8> {
        self.content.to_vec()
    }

    /// The block's 32-byte application secret, for a descendant to contain.
    /// Treat as secret: do not log or persist unencrypted.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.key.as_slice().to_vec()
    }
}

/// A block a causal decryption could not read.
#[wasm_bindgen(js_name = DecryptFailure)]
#[derive(Debug, Clone)]
pub struct JsDecryptFailure {
    content_ref: JsChangeId,
    reason: String,
}

#[wasm_bindgen(js_class = DecryptFailure)]
impl JsDecryptFailure {
    /// The `ChangeId` of the block that could not be read.
    #[wasm_bindgen(getter, js_name = contentRef)]
    pub fn content_ref(&self) -> JsChangeId {
        self.content_ref.clone()
    }

    /// Why, as text for a person to read. Its wording may change, so do not
    /// match on it.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }
}

/// The application's content, read through its `load` function.
///
/// A block `load` fails for is recorded in `failed` and reported to the traversal
/// as absent, so its key stays in `next`. Returning a `get_ciphertext` error
/// instead would drop the key.
#[derive(Debug)]
struct JsLoadStore {
    load: js_sys::Function,
    failed: RefCell<Vec<(JsChangeId, LoadError)>>,
}

impl JsLoadStore {
    async fn load(
        &self,
        id: &JsChangeId,
    ) -> Result<Option<EncryptedContent<Vec<u8>, JsChangeId>>, LoadError> {
        let called = self
            .load
            .call1(&JsValue::NULL, &id.clone().into())
            .map_err(LoadError::threw)?;
        let loaded = JsFuture::from(js_sys::Promise::resolve(&called))
            .await
            .map_err(LoadError::threw)?;
        if loaded.is_undefined() || loaded.is_null() {
            return Ok(None);
        }
        let bytes = loaded
            .dyn_into::<js_sys::Uint8Array>()
            .map_err(|_| LoadError("load returned neither bytes nor undefined".into()))?
            .to_vec();
        let encrypted = EncryptedContent::decode(&bytes)
            .map_err(|e| LoadError(format!("load returned no encrypted content: {e}")))?;
        if encrypted.content_ref != *id {
            return Err(LoadError(
                "load returned the content of another ChangeId".into(),
            ));
        }
        Ok(Some(encrypted))
    }
}

impl CiphertextStore<Local, JsChangeId, Vec<u8>> for JsLoadStore {
    type GetCiphertextError = Infallible;
    type MarkDecryptedError = Infallible;

    fn get_ciphertext<'a>(
        &'a self,
        id: &'a JsChangeId,
    ) -> <Local as FutureForm>::Future<
        'a,
        Result<Option<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Infallible>,
    > {
        Local::from_future(async move {
            match self.load(id).await {
                Ok(loaded) => Ok(loaded.map(Arc::new)),
                Err(e) => {
                    self.failed.borrow_mut().push((id.clone(), e));
                    Ok(None)
                }
            }
        })
    }

    /// Always empty since the traversal reaches content by reference only.
    fn get_ciphertext_by_group_secret_origin<'a>(
        &'a self,
        _origin: &'a Digest<GroupSecretOrigin>,
    ) -> <Local as FutureForm>::Future<
        'a,
        Result<Vec<Arc<EncryptedContent<Vec<u8>, JsChangeId>>>, Infallible>,
    > {
        Local::from_future(async { Ok(Vec::new()) })
    }

    /// Does nothing. The application keeps its content.
    fn mark_decrypted<'a>(
        &'a self,
        _id: &'a JsChangeId,
    ) -> <Local as FutureForm>::Future<'a, Result<(), Infallible>> {
        Local::from_future(async { Ok(()) })
    }
}

/// Why `load` did not yield a block.
#[derive(Debug, Error)]
#[error("{0}")]
struct LoadError(String);

impl LoadError {
    /// The thrown error's message, or the thrown value itself if it is not
    /// an `Error`.
    fn threw(err: JsValue) -> Self {
        let message = err
            .dyn_ref::<js_sys::Error>()
            .map(|e| String::from(e.message()))
            .or_else(|| err.as_string())
            .unwrap_or_else(|| format!("{err:?}"));
        LoadError(format!("load threw: {message}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{ciphertext_store::JsCiphertextStore, signer::JsSigner};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_test::*;

    #[cfg(feature = "browser_test")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    /// A `load` that returns `held` for its own `ChangeId` and `otherwise`,
    /// if given, for every other.
    fn load(held: &JsEncrypted, otherwise: Option<&JsEncrypted>) -> js_sys::Function {
        let (held_ref, held_bytes) = (held.0.content_ref.clone(), held.to_bytes());
        let other_bytes = otherwise.map(JsEncrypted::to_bytes);
        Closure::<dyn Fn(JsChangeId) -> JsValue>::new(move |id: JsChangeId| {
            match (id == held_ref, &other_bytes) {
                (true, _) => js_sys::Uint8Array::from(held_bytes.as_slice()).into(),
                (false, Some(bytes)) => js_sys::Uint8Array::from(bytes.as_slice()).into(),
                (false, None) => JsValue::UNDEFINED,
            }
        })
        .into_js_value()
        .unchecked_into()
    }

    /// Writes `contents` in a new document, each with the one before as its
    /// ancestor and `ChangeId` `[n]` for the nth, counting from 1. Returns each
    /// block with its key.
    async fn write_chain<const N: usize>(
        contents: [&[u8]; N],
    ) -> (JsKeyhive, JsDocumentId, [(JsEncrypted, Vec<u8>); N]) {
        let kh = JsKeyhive::init(
            &JsSigner::generate().await,
            &JsCiphertextStore::new_in_memory(),
            &js_sys::Function::new_no_args(""),
        )
        .await
        .expect("a keyhive starts");
        let doc = kh
            .generate_doc(vec![], &JsChangeId::new(vec![0]), vec![])
            .await
            .expect("a document is created");
        let mut ancestors = vec![];
        let mut written = vec![];
        for (n, content) in contents.into_iter().enumerate() {
            let content_ref = JsChangeId::new(vec![n as u8 + 1]);
            let keyed = kh
                .try_encrypt_with_ancestors(&doc, &content_ref, ancestors, content)
                .await
                .expect("the content encrypts");
            let key = keyed.application_secret();
            ancestors = vec![JsAncestor::new(&content_ref, &key)
                .expect("a key is 32 bytes")
                .into()];
            written.push((keyed.encrypted_content(), key));
        }
        let written = <[_; N]>::try_from(written).expect("each block was written");
        (kh, doc, written)
    }

    #[wasm_bindgen_test]
    async fn a_causal_decryption_reads_what_load_has_and_reports_the_rest() {
        let (kh, doc, [(_, grandparent_key), (parent, parent_key), (child, child_key)]) =
            write_chain([b"grandparent", b"parent", b"child"]).await;

        let read = kh
            .try_causal_decrypt(&doc, &child, load(&parent, None))
            .await
            .expect("the child decrypts");

        let complete: Vec<(Vec<u8>, Vec<u8>)> = read
            .complete()
            .iter()
            .map(|block| (block.content(), block.application_secret()))
            .collect();
        assert_eq!(
            complete,
            vec![
                (b"child".to_vec(), child_key),
                (b"parent".to_vec(), parent_key)
            ]
        );
        let next: Vec<(Vec<u8>, Vec<u8>)> = read
            .next()
            .iter()
            .map(|a| (a.content_ref().to_bytes(), a.key()))
            .collect();
        assert_eq!(next, vec![(vec![1], grandparent_key)]);
        assert!(read.failed().is_empty());
    }

    #[wasm_bindgen_test]
    async fn an_ancestor_loaded_for_another_change_id_is_refused_and_kept_to_retry() {
        let (kh, doc, [(_, grandparent_key), (parent, _), (child, _)]) =
            write_chain([b"grandparent", b"parent", b"child"]).await;

        let read = kh
            .try_causal_decrypt(&doc, &child, load(&parent, Some(&child)))
            .await
            .expect("the child decrypts");

        let complete: Vec<Vec<u8>> = read.complete().iter().map(|p| p.content()).collect();
        assert_eq!(complete, vec![b"child".to_vec(), b"parent".to_vec()]);
        let failed: Vec<(Vec<u8>, String)> = read
            .failed()
            .iter()
            .map(|f| (f.content_ref().to_bytes(), f.reason()))
            .collect();
        assert_eq!(
            failed,
            vec![(
                vec![1],
                "load returned the content of another ChangeId".to_string()
            )]
        );
        let next: Vec<(Vec<u8>, Vec<u8>)> = read
            .next()
            .iter()
            .map(|a| (a.content_ref().to_bytes(), a.key()))
            .collect();
        assert_eq!(next, vec![(vec![1], grandparent_key)]);
    }

    #[wasm_bindgen_test]
    async fn a_causal_decryption_resumes_from_the_next_of_an_earlier_one() {
        let (kh, doc, [(grandparent, _), (parent, _), (child, _)]) =
            write_chain([b"grandparent", b"parent", b"child"]).await;
        let first = kh
            .try_causal_decrypt(&doc, &child, load(&parent, None))
            .await
            .expect("the child decrypts");

        let rest = kh
            .try_causal_decrypt_from(
                &doc,
                first.next().into_iter().map(Into::into).collect(),
                load(&grandparent, None),
            )
            .await;

        let complete: Vec<Vec<u8>> = rest.complete().iter().map(|b| b.content()).collect();
        assert_eq!(complete, vec![b"grandparent".to_vec()]);
        assert!(rest.next().is_empty());
        assert!(rest.failed().is_empty());
    }

    #[wasm_bindgen_test]
    async fn an_ancestor_load_throws_for_is_reported_with_the_message_and_kept_to_retry() {
        let (kh, doc, [(_, parent_key), (child, _)]) = write_chain([b"parent", b"child"]).await;
        let throws = js_sys::Function::new_with_args("id", "throw new Error('offline')");

        let read = kh
            .try_causal_decrypt(&doc, &child, throws)
            .await
            .expect("the child decrypts");

        let failed: Vec<(Vec<u8>, String)> = read
            .failed()
            .iter()
            .map(|f| (f.content_ref().to_bytes(), f.reason()))
            .collect();
        assert_eq!(failed, vec![(vec![1], "load threw: offline".to_string())]);
        let next: Vec<(Vec<u8>, Vec<u8>)> = read
            .next()
            .iter()
            .map(|a| (a.content_ref().to_bytes(), a.key()))
            .collect();
        assert_eq!(next, vec![(vec![1], parent_key)]);
    }

    #[wasm_bindgen_test]
    async fn content_written_without_ancestors_decrypts_causally_on_its_own() {
        let (kh, doc, _) = write_chain([]).await;
        let plain = kh
            .try_encrypt(&doc, &JsChangeId::new(vec![9]), vec![], b"plain")
            .await
            .expect("the content encrypts")
            .encrypted_content();

        let read = kh
            .try_causal_decrypt(&doc, &plain, js_sys::Function::new_no_args(""))
            .await
            .expect("the content decrypts");

        let complete: Vec<Vec<u8>> = read.complete().iter().map(|b| b.content()).collect();
        assert_eq!(complete, vec![b"plain".to_vec()]);
        assert!(read.next().is_empty());
        assert!(read.failed().is_empty());
    }
}
