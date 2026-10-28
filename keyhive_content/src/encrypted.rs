//! Encrypted content, with its public metadata.
//!
//! A block has two encrypted sections: the keys of its ancestors, then its
//! body. A reader can get the ancestors' keys without decrypting the body.
//! The body is encrypted in chunks, so a block of any size streams through
//! bounded memory and any byte range decrypts on its own:
//!
//! ```text
//! "KHE" ‖ version ‖ content_ref ‖ pred_refs:32 ‖ group_secret_hash:32
//!       ‖ group_secret_origin_hash:32 ‖ ancestors_len ‖ ancestors
//!       ‖ ( nonce_i:24 ‖ ciphertext_i )+                          to the end
//!
//! ancestors = seal(ancestors_key, count ‖ ( content_ref ‖ key:32 )*,
//!                  aad = BLAKE3(doc_id ‖ header))
//! aad_i     = BLAKE3(doc_id ‖ header ‖ ancestors_len ‖ ancestors) ‖ i:u64 ‖ last:u8
//! nonce_i   = keyed BLAKE3(nonce_key, aad_i ‖ chunk_i)[..24]
//! ```
//!
//! The ancestors, in ascending order of their content refs' encodings, are
//! sealed with [`SymmetricKey::try_seal`] under a key derived from the
//! block's key. Each chunk's associated data covers the sealed ancestors, so a
//! body decrypts only with the ancestors it was encrypted with. The reverse
//! does not hold: the ancestors section is bound to the header, not to the
//! body.
//!
//! Every chunk but the last contains [`CHUNK_LEN`] plaintext bytes. The last
//! contains fewer, and is empty only when the whole plaintext is. The nonce is
//! synthetic: decryption recomputes it from the plaintext and rejects a
//! mismatch, which commits each chunk to one key. Without that, one
//! ciphertext could decrypt under two keys to two plaintexts, and an ancestors
//! section containing the second key would show its readers a different history.

use crate::{
    application_secret::{GroupSecret, GroupSecretOrigin},
    reference::ContentRef,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use core::{convert::Infallible, marker::PhantomData};
use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_bytes, decode_len, encode_bytes, encode_len},
    traits::{Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    context::Context,
    digest::Digest,
    identifier::Identifier,
    signable::{Kind, Kinded, TAG},
    siv::{nonces_match, synthetic_nonce},
    symmetric_key::SymmetricKey,
};
use tracing::instrument;

/// The first bytes of encrypted content: Keyhive's tag, then `E`, which the
/// kind registry reserves for it.
pub const CONTENT_TAG: [u8; 3] = [TAG[0], TAG[1], b'E'];

/// The version of the content format.
pub const CONTENT_VERSION: u8 = 0;

/// Plaintext bytes in every chunk but the last.
pub const CHUNK_LEN: usize = 64 * 1024;

const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;

/// Bytes a chunk adds to its plaintext: its nonce and its AEAD tag.
pub const CHUNK_OVERHEAD: usize = NONCE_LEN + AEAD_TAG_LEN;

const FULL_CHUNK: usize = CHUNK_LEN + CHUNK_OVERHEAD;

/// A block of encrypted content, with the public header readers need to find
/// its key.
///
/// `T` is the type the plaintext is expected to be. The chunks are always
/// well formed (see the [module docs](self)): construction and decoding check
/// their lengths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncryptedContent<T, Cr: ContentRef> {
    /// The content ref the block's key is derived for.
    pub content_ref: Cr,

    /// The block's predecessors, also in its key.
    pub pred_refs: Digest<PredecessorRefs<Cr>>,

    /// The CGKA group secret the block's key is derived from.
    pub group_secret_hash: Digest<GroupSecret>,

    /// The CGKA operation that generated the group secret.
    pub group_secret_origin_hash: Digest<GroupSecretOrigin>,

    /// The ancestors' content refs and keys, sealed: `nonce ‖ ciphertext`.
    ancestors: Vec<u8>,

    /// `( nonce_i ‖ ciphertext_i )+`.
    chunks: Vec<u8>,

    _plaintext_tag: PhantomData<T>,
}

impl<T, Cr: ContentRef> EncryptedContent<T, Cr> {
    /// Encrypt `plaintext` for the document `doc_id`, under a block's
    /// application key, with the keys of its `ancestors`. Where a content ref
    /// is listed more than once, its last key is kept.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt(
        key: &SymmetricKey,
        doc_id: Identifier,
        content_ref: Cr,
        pred_refs: Digest<PredecessorRefs<Cr>>,
        group_secret_hash: Digest<GroupSecret>,
        group_secret_origin_hash: Digest<GroupSecretOrigin>,
        ancestors: &[(Cr, SymmetricKey)],
        plaintext: &[u8],
    ) -> Result<Self, chacha20poly1305::Error> {
        let mut content = EncryptedContent {
            content_ref,
            pred_refs,
            group_secret_hash,
            group_secret_origin_hash,
            ancestors: Vec::new(),
            chunks: Vec::with_capacity(plaintext.len()),
            _plaintext_tag: PhantomData,
        };
        content.ancestors = ancestors_key(key).try_seal(
            &encode_ancestors(ancestors),
            &header_digest(doc_id, &content.header()),
        )?;
        let keys = ChunkKeys::new(key, doc_id, &content.prefix());
        let mut chunks = (0u64..)
            .zip(
                plaintext
                    .chunks(CHUNK_LEN)
                    .chain(plaintext.is_empty().then_some(&[][..])),
            )
            .peekable();
        while let Some((i, chunk)) = chunks.next() {
            let aad = keys.aad(i, chunks.peek().is_none());
            let nonce = keys.nonce(&aad, chunk);
            let mut buf = chunk.to_vec();
            keys.cipher
                .encrypt_in_place(&XNonce::from(nonce), &aad, &mut buf)?;
            content.chunks.extend_from_slice(&nonce);
            content.chunks.extend_from_slice(&buf);
        }
        Ok(content)
    }

    /// Decrypt the body with the block's application key, for the document
    /// `doc_id`.
    ///
    /// Each chunk must authenticate, and its nonce must be the synthetic nonce
    /// of what it decrypts to.
    #[instrument(skip_all)]
    pub fn try_decrypt(
        &self,
        key: SymmetricKey,
        doc_id: Identifier,
    ) -> Result<Vec<u8>, ContentDecryptError> {
        let keys = ChunkKeys::new(&key, doc_id, &self.prefix());
        let mut plaintext = Vec::with_capacity(self.chunks.len());
        let mut chunks = (0u64..).zip(self.chunks.chunks(FULL_CHUNK)).peekable();
        while let Some((i, chunk)) = chunks.next() {
            let (nonce, ciphertext) = chunk
                .split_first_chunk::<NONCE_LEN>()
                .expect("every chunk contains its nonce and tag");
            let aad = keys.aad(i, chunks.peek().is_none());
            let mut buf = ciphertext.to_vec();
            keys.cipher
                .decrypt_in_place(&XNonce::from(*nonce), &aad, &mut buf)?;
            if !nonces_match(&keys.nonce(&aad, &buf), nonce) {
                return Err(ContentDecryptError::NonceMismatch);
            }
            plaintext.extend_from_slice(&buf);
        }
        Ok(plaintext)
    }

    /// Decrypt the ancestors' content refs and keys, without the body, with
    /// the block's application key, for the document `doc_id`. They are in
    /// ascending order of the refs' encodings.
    ///
    /// The section is bound to the header and the document, not to the body: a
    /// section sealed with the same key and header for another body opens here
    /// too. Decrypt the body as well to know the two were sealed together.
    ///
    /// Fails with [`ContentDecryptError::Decryption`] if the key or document is
    /// wrong, the header or the section was changed, or the section's nonce is
    /// not synthetic. Fails with [`ContentDecryptError::MalformedAncestors`]
    /// if the section decrypts to anything other than a well-formed list.
    #[instrument(skip_all)]
    pub fn try_decrypt_ancestors(
        &self,
        key: SymmetricKey,
        doc_id: Identifier,
    ) -> Result<Vec<(Cr, SymmetricKey)>, ContentDecryptError> {
        let encoded = ancestors_key(&key)
            .try_open(&self.ancestors, &header_digest(doc_id, &self.header()))?;
        decode_ancestors(&encoded).map_err(ContentDecryptError::MalformedAncestors)
    }

    /// The chunks: `( nonce_i ‖ ciphertext_i )+`.
    pub fn chunks(&self) -> &[u8] {
        &self.chunks
    }

    /// BLAKE3 of the encoding, which starts with `KHE`. Identifies these bytes,
    /// not the content. The same plaintext under another key differs.
    pub fn digest(&self) -> Digest<Self> {
        Digest::from(blake3::hash(self.encode().as_bytes()))
    }

    /// `"KHE" ‖ version ‖ content_ref ‖ pred_refs ‖ group_secret_hash ‖ group_secret_origin_hash`.
    fn header(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_header(&mut out);
        out
    }

    fn encode_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&CONTENT_TAG);
        out.push(CONTENT_VERSION);
        self.content_ref.encode_into(out);
        self.pred_refs.encode_into(out);
        self.group_secret_hash.encode_into(out);
        self.group_secret_origin_hash.encode_into(out);
    }

    /// Everything before the chunks: the header and the sealed ancestors.
    fn prefix(&self) -> Vec<u8> {
        let mut out = self.header();
        encode_bytes(&self.ancestors, &mut out);
        out
    }
}

/// The header, the sealed ancestors with their length, then the chunks to the
/// end. It is not self-delimiting, so a container of several frames must
/// store each frame's length.
impl<T, Cr: ContentRef> Encode for EncryptedContent<T, Cr> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.encode_header(out);
        encode_bytes(&self.ancestors, out);
        out.extend_from_slice(&self.chunks);
    }
}

impl<T, Cr: ContentRef> Decode for EncryptedContent<T, Cr> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (tag, rest) = bytes
            .split_first_chunk::<3>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        if tag[..2] != TAG {
            return Err(DecodeError::NotKeyhive);
        }
        if tag[2] != CONTENT_TAG[2] {
            return Err(DecodeError::UnexpectedKind(tag[2]));
        }
        let (&version, rest) = rest.split_first().ok_or(DecodeError::UnexpectedEnd)?;
        if version != CONTENT_VERSION {
            return Err(DecodeError::UnsupportedVersion {
                kind: CONTENT_TAG[2],
                version,
            });
        }
        let (content_ref, rest) = Cr::decode_next(rest)?;
        let (pred_refs, rest) = Digest::decode_next(rest)?;
        let (group_secret_hash, rest) = Digest::decode_next(rest)?;
        let (group_secret_origin_hash, rest) = Digest::decode_next(rest)?;
        let (ancestors, chunks) = decode_bytes(rest)?;
        if ancestors.len() < MIN_ANCESTORS_LEN {
            return Err(DecodeError::InvalidField("ancestors"));
        }
        chunk_count(chunks.len()).ok_or(DecodeError::InvalidField("chunks"))?;
        Ok(EncryptedContent {
            content_ref,
            pred_refs,
            group_secret_hash,
            group_secret_origin_hash,
            ancestors: ancestors.to_vec(),
            chunks: chunks.to_vec(),
            _plaintext_tag: PhantomData,
        })
    }
}

/// Encrypts arbitrary bytes and ancestors, with arbitrary header fields, under
/// an arbitrary key and document, so the sections are always well formed. A
/// full chunk may come before the arbitrary tail, so layouts with a non-final
/// chunk are drawn too.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T, Cr: ContentRef + arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
    for EncryptedContent<T, Cr>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = SymmetricKey::from(<[u8; 32]>::arbitrary(u)?);
        let doc_id = Identifier::arbitrary(u)?;
        let full_chunk_first = bool::arbitrary(u)?;
        let fill = u8::arbitrary(u)?;
        let mut plaintext = alloc::vec![fill; if full_chunk_first { CHUNK_LEN } else { 0 }];
        plaintext.extend(Vec::<u8>::arbitrary(u)?);
        let ancestors: Vec<(Cr, SymmetricKey)> = Vec::<(Cr, [u8; 32])>::arbitrary(u)?
            .into_iter()
            .map(|(content_ref, key)| (content_ref, SymmetricKey::from(key)))
            .collect();
        EncryptedContent::encrypt(
            &key,
            doc_id,
            Cr::arbitrary(u)?,
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            &ancestors,
            &plaintext,
        )
        .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

/// The content refs a block references as its predecessors. Only their
/// digest is used, hashed into the block's key, so the type is never
/// built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredecessorRefs<Cr>(Infallible, PhantomData<Cr>);

impl<Cr: ContentRef> PredecessorRefs<Cr> {
    /// The digest of `refs` as a set: `count ‖ ref*`, with each distinct ref
    /// once, in ascending order of its encoding. Neither the order a writer
    /// lists them in nor a repeat changes the block's key.
    pub fn digest(refs: &[Cr]) -> Digest<PredecessorRefs<Cr>> {
        let encoded: BTreeSet<Vec<u8>> = refs.iter().map(|r| r.encode().into_bytes()).collect();
        let mut bytes = Vec::new();
        encode_len(encoded.len(), &mut bytes);
        encoded.iter().for_each(|r| bytes.extend_from_slice(r));
        Digest::of_bytes(&bytes)
    }
}

impl<Cr> Kinded for PredecessorRefs<Cr> {
    const KIND: Kind = Kind::PREDECESSOR_REFS;
    const VERSION: u8 = 0;
}

/// Why content did not decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContentDecryptError {
    /// A chunk or the ancestors section does not authenticate: the wrong key
    /// or document, or the ciphertext was changed. For the ancestors section,
    /// this also covers a nonce that is not synthetic.
    #[error("content does not decrypt: wrong key or document, or altered")]
    Decryption,

    /// A chunk authenticates, but its nonce is not the synthetic nonce of what
    /// it decrypts to, so it may have been built to decrypt under another key.
    #[error("a chunk's nonce does not match its plaintext")]
    NonceMismatch,

    /// The ancestors section decrypts, but not to a well-formed list: each ref
    /// once, in ascending order, with nothing after. Only a writer holding the
    /// block's key can produce this.
    #[error("the ancestors section is malformed: {0}")]
    MalformedAncestors(DecodeError),
}

/// `chacha20poly1305::Error` contains no details, and is an `Error` only with
/// `std`, so it is not kept as a source.
impl From<chacha20poly1305::Error> for ContentDecryptError {
    fn from(_: chacha20poly1305::Error) -> Self {
        ContentDecryptError::Decryption
    }
}

/// The bytes [`SymmetricKey::try_seal`] adds: a nonce and an AEAD tag.
const SEAL_OVERHEAD: usize = NONCE_LEN + AEAD_TAG_LEN;

/// The shortest sealed ancestors section: an empty list, which is one byte of
/// count.
const MIN_ANCESTORS_LEN: usize = SEAL_OVERHEAD + 1;

/// The key a block's ancestors are sealed under, from its application key.
fn ancestors_key(key: &SymmetricKey) -> SymmetricKey {
    SymmetricKey::from(Context::CONTENT_ANCESTORS_KEY.derive_key(key.as_slice()))
}

/// `BLAKE3(doc_id ‖ bytes)`, under the content header's context.
fn header_digest(doc_id: Identifier, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Context::CONTENT_HEADER.hasher();
    hasher.update(doc_id.as_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// `count ‖ ( content_ref ‖ key )*`, each content ref once, in ascending order
/// of their encodings, so the bytes do not depend on the order given. Where a
/// ref is listed more than once, its last key is kept.
fn encode_ancestors<Cr: ContentRef>(ancestors: &[(Cr, SymmetricKey)]) -> Vec<u8> {
    let entries: BTreeMap<Vec<u8>, [u8; 32]> = ancestors
        .iter()
        .map(|(content_ref, key)| (content_ref.encode().into_bytes(), (*key).into()))
        .collect();
    let mut out = Vec::new();
    encode_len(entries.len(), &mut out);
    for (content_ref, key) in &entries {
        out.extend_from_slice(content_ref);
        out.extend_from_slice(key);
    }
    out
}

/// Refuses refs out of order or repeated, and bytes left over, so each list
/// has one encoding.
fn decode_ancestors<Cr: ContentRef>(bytes: &[u8]) -> Result<Vec<(Cr, SymmetricKey)>, DecodeError> {
    let (count, mut rest) = decode_len(bytes)?;
    let mut ancestors = Vec::new();
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let (content_ref, after_ref) = Cr::decode_next(rest)?;
        let encoded = &rest[..rest.len() - after_ref.len()];
        if previous.is_some_and(|p| p >= encoded) {
            return Err(DecodeError::UnsortedKeys);
        }
        let (key, after_key) = <[u8; 32]>::decode_next(after_ref)?;
        ancestors.push((content_ref, SymmetricKey::from(key)));
        previous = Some(encoded);
        rest = after_key;
    }
    if !rest.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(ancestors)
}

/// The keys and prefix digest every chunk of one block uses.
struct ChunkKeys {
    cipher: XChaCha20Poly1305,
    nonce_key: [u8; 32],
    prefix_digest: [u8; 32],
}

impl ChunkKeys {
    /// `prefix` is everything before the chunks: the header and the sealed
    /// ancestors.
    fn new(key: &SymmetricKey, doc_id: Identifier, prefix: &[u8]) -> Self {
        ChunkKeys {
            cipher: XChaCha20Poly1305::new(
                &Context::CONTENT_ENCRYPTION_KEY
                    .derive_key(key.as_slice())
                    .into(),
            ),
            nonce_key: Context::CONTENT_NONCE_KEY.derive_key(key.as_slice()),
            prefix_digest: header_digest(doc_id, prefix),
        }
    }

    /// `prefix_digest ‖ i:u64 ‖ last:u8`.
    fn aad(&self, i: u64, last: bool) -> [u8; 41] {
        let mut aad = [0; 41];
        aad[..32].copy_from_slice(&self.prefix_digest);
        aad[32..40].copy_from_slice(&i.to_be_bytes());
        aad[40] = u8::from(last);
        aad
    }

    fn nonce(&self, aad: &[u8; 41], chunk: &[u8]) -> [u8; NONCE_LEN] {
        synthetic_nonce(&self.nonce_key, &[aad, chunk])
    }
}

/// The number of chunks in `len` bytes of them, if they are well formed: at
/// least one, every one but the last full, and the last non-empty unless it
/// is the only one. Each plaintext has exactly one chunking.
fn chunk_count(len: usize) -> Option<usize> {
    let count = len.div_ceil(FULL_CHUNK).max(1);
    let last = len.checked_sub((count - 1) * FULL_CHUNK)?;
    let well_formed = last >= CHUNK_OVERHEAD && (count == 1 || last > CHUNK_OVERHEAD);
    well_formed.then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::SigningKey;

    type Content = EncryptedContent<Vec<u8>, [u8; 32]>;

    fn doc(n: u8) -> Identifier {
        Identifier::from(&SigningKey::from_bytes(&[n; 32]))
    }

    fn key(n: u8) -> SymmetricKey {
        SymmetricKey::from([n; 32])
    }

    fn encrypt_with(ancestors: &[([u8; 32], SymmetricKey)], plaintext: &[u8]) -> Content {
        EncryptedContent::encrypt(
            &key(1),
            doc(1),
            [2; 32],
            PredecessorRefs::digest(&[[3; 32]]),
            [4; 32].into(),
            [5; 32].into(),
            ancestors,
            plaintext,
        )
        .expect("a fresh key encrypts")
    }

    fn encrypt(plaintext: &[u8]) -> Content {
        encrypt_with(&[([3; 32], key(6))], plaintext)
    }

    fn reencoded(content: &Content, edit: impl FnOnce(&mut Vec<u8>)) -> Content {
        let mut bytes = content.encode().into_bytes();
        edit(&mut bytes);
        Content::decode(&bytes).expect("the edit keeps the chunk lengths well formed")
    }

    /// The header: tag, version, content ref and three digests.
    const HEADER_LEN: usize = 3 + 1 + 32 + 3 * 32;

    /// Where [`encrypt`]'s chunks start: after the header, the section's
    /// length, and the sealed count, ref and key of its one ancestor. The
    /// length and the count take one byte each.
    const CHUNKS_AT: usize = HEADER_LEN + 1 + SEAL_OVERHEAD + 1 + 64;

    const SIZES: [usize; 8] = [
        0,
        1,
        CHUNK_LEN - 1,
        CHUNK_LEN,
        CHUNK_LEN + 1,
        2 * CHUNK_LEN,
        2 * CHUNK_LEN + 1,
        3 * CHUNK_LEN - 7,
    ];

    #[test]
    fn content_round_trips_at_sizes_around_chunk_boundaries() {
        for len in SIZES {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let content = encrypt(&plaintext);
            let chunks = len.div_ceil(CHUNK_LEN).max(1);
            assert_eq!(
                content.chunks().len(),
                len + chunks * CHUNK_OVERHEAD,
                "{len} bytes take {chunks} chunks"
            );
            assert_eq!(
                Content::decode(content.encode().as_bytes()).as_ref(),
                Ok(&content),
                "{len} bytes decode to what encoded them"
            );
            assert_eq!(
                content.try_decrypt(key(1), doc(1)),
                Ok(plaintext),
                "{len} bytes decrypt"
            );
        }
    }

    #[test]
    fn a_chunk_holds_64_kib_of_plaintext() {
        assert_eq!(
            encrypt(&vec![0; 65_536]).chunks().len(),
            65_536 + CHUNK_OVERHEAD
        );
        assert_eq!(
            encrypt(&vec![0; 65_537]).chunks().len(),
            65_537 + 2 * CHUNK_OVERHEAD
        );
    }

    #[test]
    fn the_encoding_starts_with_the_header() {
        let bytes = encrypt(b"hi").encode().into_bytes();
        assert_eq!(&bytes[..4], b"KHE\x00");
        assert_eq!(bytes.len(), CHUNKS_AT + 2 + CHUNK_OVERHEAD);
    }

    #[test]
    fn the_wrong_key_or_document_does_not_decrypt() {
        let content = encrypt(b"secret");
        for (what, key, doc) in [("key", key(9), doc(1)), ("document", key(1), doc(9))] {
            assert_eq!(
                content.try_decrypt(key, doc),
                Err(ContentDecryptError::Decryption),
                "body, wrong {what}"
            );
            assert_eq!(
                content.try_decrypt_ancestors(key, doc),
                Err(ContentDecryptError::Decryption),
                "ancestors, wrong {what}"
            );
        }
    }

    /// Every header field is in both sections' associated data.
    #[test]
    fn an_edited_header_does_not_decrypt() {
        let content = encrypt(b"secret");
        let fields = [
            ("content_ref", 4),
            ("pred_refs", 36),
            ("group_secret_hash", 68),
            ("group_secret_origin_hash", 100),
        ];
        for (field, at) in fields {
            let edited = reencoded(&content, |b| b[at] ^= 1);
            assert_eq!(
                edited.try_decrypt(key(1), doc(1)),
                Err(ContentDecryptError::Decryption),
                "body, {field} edited"
            );
            assert_eq!(
                edited.try_decrypt_ancestors(key(1), doc(1)),
                Err(ContentDecryptError::Decryption),
                "ancestors, {field} edited"
            );
        }
    }

    #[test]
    fn a_body_does_not_decrypt_with_another_blocks_ancestors() {
        let other = encrypt_with(&[([8; 32], key(8))], b"secret");
        let content = encrypt(b"secret");
        let spliced = reencoded(&content, |b| {
            b.splice(HEADER_LEN..CHUNKS_AT, other.prefix()[HEADER_LEN..].to_vec());
        });
        assert_eq!(
            spliced.try_decrypt_ancestors(key(1), doc(1)),
            Ok(vec![([8; 32], key(8))])
        );
        assert_eq!(
            spliced.try_decrypt(key(1), doc(1)),
            Err(ContentDecryptError::Decryption)
        );
    }

    #[test]
    fn a_repeated_ancestor_keeps_its_last_key() {
        let given = [([2; 32], key(1)), ([1; 32], key(2)), ([2; 32], key(3))];
        assert_eq!(
            encrypt_with(&given, b"").try_decrypt_ancestors(key(1), doc(1)),
            Ok(vec![([1; 32], key(2)), ([2; 32], key(3))])
        );
    }

    #[test]
    fn ancestors_decrypt_in_order_of_their_refs() {
        bolero::check!()
            .with_arbitrary::<Vec<([u8; 32], [u8; 32])>>()
            .for_each(|ancestors| {
                let given: Vec<_> = ancestors
                    .iter()
                    .map(|(r, k)| (*r, SymmetricKey::from(*k)))
                    .collect();
                let expected: Vec<_> = BTreeMap::from_iter(given.clone()).into_iter().collect();
                assert_eq!(
                    encrypt_with(&given, b"").try_decrypt_ancestors(key(1), doc(1)),
                    Ok(expected)
                );
            });
    }

    #[test]
    fn decoding_ancestors_refuses_unsorted_or_repeated_refs() {
        let entry = |n: u8| [[n; 32], [0; 32]].concat();
        for (what, entries) in [
            ("unsorted", [entry(2), entry(1)]),
            ("repeated", [entry(1), entry(1)]),
        ] {
            let bytes = [vec![2], entries.concat()].concat();
            assert_eq!(
                decode_ancestors::<[u8; 32]>(&bytes),
                Err(DecodeError::UnsortedKeys),
                "{what}"
            );
        }
    }

    #[test]
    fn an_ancestor_list_has_exactly_one_encoding() {
        use keyhive_codec::laws::Mutation;

        bolero::check!()
            .with_arbitrary::<(Vec<([u8; 32], [u8; 32])>, Mutation, Vec<Mutation>)>()
            .for_each(|(ancestors, first, rest)| {
                let given: Vec<_> = ancestors
                    .iter()
                    .map(|(r, k)| (*r, SymmetricKey::from(*k)))
                    .collect();
                let mut bytes = encode_ancestors(&given);
                for m in core::iter::once(first).chain(rest) {
                    m.apply(&mut bytes);
                }
                if let Ok(decoded) = decode_ancestors::<[u8; 32]>(&bytes) {
                    assert_eq!(encode_ancestors(&decoded), bytes);
                }
            });
    }

    #[test]
    fn a_flipped_bit_in_any_chunk_does_not_decrypt() {
        let content = encrypt(&vec![7; 2 * CHUNK_LEN + 3]);
        for at in [
            CHUNKS_AT,
            CHUNKS_AT + FULL_CHUNK + 30,
            CHUNKS_AT + 2 * FULL_CHUNK + 1,
        ] {
            let edited = reencoded(&content, |b| b[at] ^= 1);
            assert!(edited.try_decrypt(key(1), doc(1)).is_err(), "byte {at}");
        }
    }

    /// Truncation at a chunk boundary, reordering and appending all leave
    /// well-formed lengths, and are caught by each chunk's index and final flag.
    #[test]
    fn dropped_reordered_or_appended_chunks_do_not_decrypt() {
        let content = encrypt(&vec![7; 3 * CHUNK_LEN]);
        let chunk = |i: usize| CHUNKS_AT + i * FULL_CHUNK..CHUNKS_AT + (i + 1) * FULL_CHUNK;

        let truncated = reencoded(&content, |b| b.truncate(chunk(2).start));
        let reordered = reencoded(&content, |b| {
            let first = b[chunk(0)].to_vec();
            let second = b[chunk(1)].to_vec();
            b[chunk(0)].copy_from_slice(&second);
            b[chunk(1)].copy_from_slice(&first);
        });
        let appended = reencoded(&content, |b| {
            let last = b[chunk(2)].to_vec();
            b.extend_from_slice(&last);
        });
        for (what, edited) in [
            ("truncated", truncated),
            ("reordered", reordered),
            ("appended", appended),
        ] {
            assert_eq!(
                edited.try_decrypt(key(1), doc(1)),
                Err(ContentDecryptError::Decryption),
                "{what}"
            );
        }
    }

    /// A chunk that authenticates under the right key, but whose nonce is not
    /// its synthetic nonce, is refused: the check after decryption is what
    /// commits a chunk to one key.
    #[test]
    fn a_chunk_whose_nonce_is_not_synthetic_is_refused() {
        let content = encrypt(b"genuine");
        let keys = ChunkKeys::new(&key(1), doc(1), &content.prefix());
        let nonce = XNonce::from([9; NONCE_LEN]);
        let mut buf = b"forged".to_vec();
        keys.cipher
            .encrypt_in_place(&nonce, &keys.aad(0, true), &mut buf)
            .expect("encrypts");
        let forged = reencoded(&content, |b| {
            b.truncate(CHUNKS_AT);
            b.extend_from_slice(&nonce);
            b.extend_from_slice(&buf);
        });
        assert_eq!(
            forged.try_decrypt(key(1), doc(1)),
            Err(ContentDecryptError::NonceMismatch)
        );
    }

    #[test]
    fn decoding_refuses_another_format() {
        let bytes = encrypt(b"hi").encode().into_bytes();
        let with = |at: usize, byte: u8| {
            let mut b = bytes.clone();
            b[at] = byte;
            Content::decode(&b)
        };
        assert_eq!(with(0, b'X'), Err(DecodeError::NotKeyhive));
        assert_eq!(with(2, b'D'), Err(DecodeError::UnexpectedKind(b'D')));
        assert_eq!(
            with(3, 1),
            Err(DecodeError::UnsupportedVersion {
                kind: b'E',
                version: 1
            })
        );
    }

    /// Lengths that no chunking produces: none, too short for a nonce and tag,
    /// a final chunk too short, and an empty final chunk after a full one.
    #[test]
    fn decoding_refuses_malformed_chunks() {
        let header = encrypt(b"").encode().into_bytes()[..CHUNKS_AT].to_vec();
        for len in [
            0,
            CHUNK_OVERHEAD - 1,
            FULL_CHUNK + 10,
            FULL_CHUNK + CHUNK_OVERHEAD,
        ] {
            let bytes = [header.clone(), vec![0; len]].concat();
            assert_eq!(
                Content::decode(&bytes),
                Err(DecodeError::InvalidField("chunks")),
                "{len} bytes of chunks"
            );
        }
    }

    #[test]
    fn decoding_refuses_an_ancestors_section_shorter_than_an_empty_list_sealed() {
        let header = encrypt(b"").encode().into_bytes()[..HEADER_LEN].to_vec();
        let with_section = |len: usize| {
            let bytes = [
                header.clone(),
                vec![len as u8],
                vec![0; len + CHUNK_OVERHEAD],
            ]
            .concat();
            Content::decode(&bytes).map(|_| ())
        };
        assert_eq!(
            with_section(SEAL_OVERHEAD),
            Err(DecodeError::InvalidField("ancestors"))
        );
        assert_eq!(with_section(SEAL_OVERHEAD + 1), Ok(()));
    }

    /// Any well-formed block decodes to itself, and whatever still decodes
    /// near a valid encoding (a tag, length or chunk byte changed, bytes cut
    /// or appended) re-encodes to exactly those bytes.
    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Content>();
        keyhive_codec::laws::canonical_near::<Content>();
    }

    #[test]
    fn small_content_round_trips_through_its_bytes() {
        bolero::check!()
            .with_arbitrary::<(Vec<u8>, [u8; 32], [u8; 32])>()
            .for_each(|(plaintext, content_ref, doc_seed)| {
                let doc = Identifier::from(&SigningKey::from_bytes(doc_seed));
                let content: Content = EncryptedContent::encrypt(
                    &key(1),
                    doc,
                    *content_ref,
                    PredecessorRefs::digest(&[]),
                    [4; 32].into(),
                    [5; 32].into(),
                    &[],
                    plaintext,
                )
                .expect("encrypts");
                let read = Content::decode(content.encode().as_bytes()).expect("decodes");
                assert_eq!(read.try_decrypt(key(1), doc).as_ref(), Ok(plaintext));
            });
    }

    #[test]
    fn the_predecessor_digest_hashes_the_refs_in_ascending_order() {
        assert_eq!(
            PredecessorRefs::digest(&[[7u8; 32], [3; 32]])
                .raw
                .to_hex()
                .as_str(),
            "f7e5bf5486ee0006ccd8280bb1f93abb14c29172b7eb3123d69f8cffae807041"
        );
    }

    #[test]
    fn a_repeated_predecessor_is_hashed_once() {
        assert_eq!(
            PredecessorRefs::digest(&[[3u8; 32], [3; 32]]),
            PredecessorRefs::digest(&[[3u8; 32]])
        );
    }

    /// Pins the v1 derivations: a change here changes every ciphertext. The
    /// predecessor digest is BLAKE3 over `"KH" ‖ 'H' ‖ 0x00 ‖ count ‖ refs`,
    /// with each distinct ref once, sorted.
    #[test]
    fn known_answer() {
        let content = encrypt(b"keyhive");
        assert_eq!(
            blake3::hash(content.encode().as_bytes()).to_hex().as_str(),
            "652227fba115393b417f868570998aa4e7fa275c7dbdcc62cf0f03f02ef5c23b"
        );
        assert_eq!(
            PredecessorRefs::digest(&[[3u8; 32]]).raw.to_hex().as_str(),
            "55450d263093c72d5367b8002c03f45eabcb4096e3e3344b3d628df936039a4e"
        );
    }
}
