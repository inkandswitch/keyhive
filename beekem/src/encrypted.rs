//! Encrypted content and secrets, with their public metadata.
//!
//! Content is encrypted in chunks, so a block of any size streams through
//! bounded memory and any byte range decrypts on its own:
//!
//! ```text
//! "KHE" ‖ version ‖ content_ref ‖ pred_refs:32 ‖ pcs_key_hash:32 ‖ pcs_update_op:32
//!       ‖ ( nonce_i:24 ‖ ciphertext_i )+                          to the end
//!
//! aad_i   = BLAKE3(doc_id ‖ header) ‖ i:u64 ‖ last:u8
//! nonce_i = keyed BLAKE3(nonce_key, aad_i ‖ chunk_i)[..24]
//! ```
//!
//! Every chunk but the last holds [`CHUNK_LEN`] plaintext bytes; the last holds
//! fewer, and is empty only when the whole plaintext is. The nonce is
//! synthetic: decryption recomputes it from the plaintext and rejects a
//! mismatch, which commits each chunk to one key. Without that, one
//! ciphertext could decrypt under two keys to two plaintexts, and a causal
//! envelope naming the second key would show its readers a different history.

use crate::{error::CgkaError, id::TreeId, operation::CgkaOperation, pcs_key::PcsKey};
use alloc::vec::Vec;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use core::{convert::Infallible, marker::PhantomData};
use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_bytes, encode_bytes, encode_list},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signable::{Kind, Kinded, TAG},
    signed::SerdeSigned,
    siv::nonces_match,
    symmetric_key::SymmetricKey,
};
use serde::{Deserialize, Serialize};
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

/// Bytes [`SymmetricKey::try_seal`] adds to its plaintext: its nonce and its
/// AEAD tag.
const SEAL_OVERHEAD: usize = NONCE_LEN + AEAD_TAG_LEN;

const FULL_CHUNK: usize = CHUNK_LEN + CHUNK_OVERHEAD;

const HEADER_CONTEXT: &str = "/keyhive/content/header/v1/2026-10-26";
const ENCRYPTION_KEY_CONTEXT: &str = "/keyhive/content/encryption-key/v1/2026-10-26";
const NONCE_KEY_CONTEXT: &str = "/keyhive/content/nonce-key/v1/2026-10-26";

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

    /// The PCS key the block's key is derived from.
    pub pcs_key_hash: Digest<PcsKey>,

    /// The CGKA update that produced that PCS key.
    pub pcs_update_op_hash: Digest<SerdeSigned<CgkaOperation>>,

    /// `( nonce_i ‖ ciphertext_i )+`.
    chunks: Vec<u8>,

    _plaintext_tag: PhantomData<T>,
}

impl<T, Cr: ContentRef> EncryptedContent<T, Cr> {
    /// Encrypt `plaintext` for the document `doc_id`, under a block's
    /// application key.
    #[instrument(skip_all)]
    pub fn encrypt(
        key: &SymmetricKey,
        doc_id: TreeId,
        content_ref: Cr,
        pred_refs: Digest<PredecessorRefs<Cr>>,
        pcs_key_hash: Digest<PcsKey>,
        pcs_update_op_hash: Digest<SerdeSigned<CgkaOperation>>,
        plaintext: &[u8],
    ) -> Result<Self, chacha20poly1305::Error> {
        let mut content = EncryptedContent {
            content_ref,
            pred_refs,
            pcs_key_hash,
            pcs_update_op_hash,
            chunks: Vec::with_capacity(plaintext.len()),
            _plaintext_tag: PhantomData,
        };
        let keys = ChunkKeys::new(key, doc_id, &content.header());
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

    /// Decrypt with the block's application key, for the document `doc_id`.
    ///
    /// Each chunk must authenticate, and its nonce must be the synthetic nonce
    /// of what it decrypts to.
    #[instrument(skip_all)]
    pub fn try_decrypt(
        &self,
        key: SymmetricKey,
        doc_id: TreeId,
    ) -> Result<Vec<u8>, ContentDecryptError> {
        let keys = ChunkKeys::new(&key, doc_id, &self.header());
        let mut plaintext = Vec::with_capacity(self.chunks.len());
        let mut chunks = (0u64..).zip(self.chunks.chunks(FULL_CHUNK)).peekable();
        while let Some((i, chunk)) = chunks.next() {
            let (nonce, ciphertext) = chunk
                .split_first_chunk::<NONCE_LEN>()
                .expect("every chunk holds its nonce and tag");
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

    /// The chunks: `( nonce_i ‖ ciphertext_i )+`.
    pub fn chunks(&self) -> &[u8] {
        &self.chunks
    }

    /// BLAKE3 of the encoding, which starts with `KHE`. Identifies these bytes,
    /// not the content: the same plaintext under another key differs.
    pub fn digest(&self) -> Digest<Self> {
        Digest::from(blake3::hash(self.encode().as_bytes()))
    }

    /// `"KHE" ‖ version ‖ content_ref ‖ pred_refs ‖ pcs_key_hash ‖ pcs_update_op`.
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
        self.pcs_key_hash.encode_into(out);
        self.pcs_update_op_hash.encode_into(out);
    }
}

/// The header, then the chunks to the end. Not self-delimiting: a container
/// holding several frames each with its length.
impl<T, Cr: ContentRef> Encode for EncryptedContent<T, Cr> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.encode_header(out);
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
        let (pcs_key_hash, rest) = Digest::decode_next(rest)?;
        let (pcs_update_op_hash, chunks) = Digest::decode_next(rest)?;
        chunk_count(chunks.len()).ok_or(DecodeError::InvalidField("chunks"))?;
        Ok(EncryptedContent {
            content_ref,
            pred_refs,
            pcs_key_hash,
            pcs_update_op_hash,
            chunks: chunks.to_vec(),
            _plaintext_tag: PhantomData,
        })
    }
}

/// Encrypts arbitrary bytes, with arbitrary header fields, under an arbitrary
/// key and document, so the chunks are always well formed. A full chunk may
/// come before the arbitrary tail, so layouts with a non-final chunk are drawn
/// too.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T, Cr: ContentRef + arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
    for EncryptedContent<T, Cr>
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key = SymmetricKey::from(<[u8; 32]>::arbitrary(u)?);
        let doc_id = TreeId::arbitrary(u)?;
        let full_chunk_first = bool::arbitrary(u)?;
        let fill = u8::arbitrary(u)?;
        let mut plaintext = alloc::vec![fill; if full_chunk_first { CHUNK_LEN } else { 0 }];
        plaintext.extend(Vec::<u8>::arbitrary(u)?);
        EncryptedContent::encrypt(
            &key,
            doc_id,
            Cr::arbitrary(u)?,
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            Digest::from(<[u8; 32]>::arbitrary(u)?),
            &plaintext,
        )
        .map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

/// The content refs a block names as its predecessors. Only their digest is
/// used, hashed into the block's key, so the type is never built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PredecessorRefs<Cr>(Infallible, PhantomData<Cr>);

impl<Cr: ContentRef> PredecessorRefs<Cr> {
    /// The digest of `refs`, in the order given: `count ‖ ref*`.
    pub fn digest(refs: &[Cr]) -> Digest<PredecessorRefs<Cr>> {
        let mut bytes = Vec::new();
        encode_list(refs, &mut bytes);
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
    /// A chunk does not authenticate: the wrong key or document, or the
    /// ciphertext was changed.
    #[error("content does not decrypt: wrong key or document, or altered")]
    Decryption,

    /// A chunk authenticates, but its nonce is not the synthetic nonce of what
    /// it decrypts to, so it may have been built to decrypt under another key.
    #[error("a chunk's nonce does not match its plaintext")]
    NonceMismatch,
}

/// `chacha20poly1305::Error` carries nothing, and is an `Error` only with
/// `std`, so it is not kept as a source.
impl From<chacha20poly1305::Error> for ContentDecryptError {
    fn from(_: chacha20poly1305::Error) -> Self {
        ContentDecryptError::Decryption
    }
}

/// The keys and header digest every chunk of one block uses.
struct ChunkKeys {
    cipher: XChaCha20Poly1305,
    nonce_key: [u8; 32],
    header_digest: [u8; 32],
}

impl ChunkKeys {
    fn new(key: &SymmetricKey, doc_id: TreeId, header: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(HEADER_CONTEXT);
        hasher.update(doc_id.as_bytes());
        hasher.update(header);
        ChunkKeys {
            cipher: XChaCha20Poly1305::new(
                &blake3::derive_key(ENCRYPTION_KEY_CONTEXT, key.as_slice()).into(),
            ),
            nonce_key: blake3::derive_key(NONCE_KEY_CONTEXT, key.as_slice()),
            header_digest: *hasher.finalize().as_bytes(),
        }
    }

    /// `header_digest ‖ i:u64 ‖ last:u8`.
    fn aad(&self, i: u64, last: bool) -> [u8; 41] {
        let mut aad = [0; 41];
        aad[..32].copy_from_slice(&self.header_digest);
        aad[32..40].copy_from_slice(&i.to_be_bytes());
        aad[40] = u8::from(last);
        aad
    }

    fn nonce(&self, aad: &[u8; 41], chunk: &[u8]) -> [u8; NONCE_LEN] {
        let mut hasher = blake3::Hasher::new_keyed(&self.nonce_key);
        hasher.update(aad);
        hasher.update(chunk);
        let mut nonce = [0; NONCE_LEN];
        hasher.finalize_xof().fill(&mut nonce);
        nonce
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

/// A secret sealed for the holder of `paired_pk`'s secret, under the key a
/// Diffie-Hellman exchange between that holder and the encrypter gives.
///
/// The seal's associated data is the tree and both public keys of the
/// exchange (`tree_id ‖ encrypter_pk ‖ paired_pk`), and opening checks the
/// synthetic nonce ([`SymmetricKey::try_open`]). A ciphertext therefore opens
/// only in the tree, and between the two keys, it was sealed for, and under
/// only one key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptedSecret<T> {
    /// `nonce ‖ ciphertext ‖ tag`, from [`SymmetricKey::try_seal`].
    sealed: Vec<u8>,

    /// The [`ShareKey`] used as a Diffie Hellman partner when encrypting.
    pub paired_pk: ShareKey,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T> EncryptedSecret<T> {
    /// Open with the encrypter's secret key.
    #[instrument(skip_all)]
    pub fn try_encrypter_decrypt(
        &self,
        doc_id: TreeId,
        encrypter_sk: &ShareSecretKey,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        encrypter_sk.derive_symmetric_key(&self.paired_pk).try_open(
            &self.sealed,
            &node_secret_aad(doc_id, &encrypter_sk.share_key(), &self.paired_pk),
        )
    }

    /// Open with `paired_sk`, the secret of [`Self::paired_pk`], given the
    /// encrypter's public key.
    #[instrument(skip_all)]
    pub fn try_paired_decrypt(
        &self,
        doc_id: TreeId,
        paired_sk: &ShareSecretKey,
        encrypter_pk: &ShareKey,
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        paired_sk.derive_symmetric_key(encrypter_pk).try_open(
            &self.sealed,
            &node_secret_aad(doc_id, encrypter_pk, &self.paired_pk),
        )
    }
}

/// A symmetric key derived from a Diffie-Hellman exchange, with the public
/// keys of both sides.
pub struct PairedKey {
    key: SymmetricKey,
    encrypter_pk: ShareKey,
    paired_pk: ShareKey,
}

impl PairedKey {
    /// Derive the key `paired_pk`'s holder needs to decrypt what `sk` encrypts.
    pub fn new(sk: &ShareSecretKey, paired_pk: &ShareKey) -> Self {
        PairedKey {
            key: sk.derive_symmetric_key(paired_pk),
            encrypter_pk: sk.share_key(),
            paired_pk: *paired_pk,
        }
    }
}

/// `tree_id ‖ encrypter_pk ‖ paired_pk`, the associated data a node secret is
/// sealed under.
fn node_secret_aad(doc_id: TreeId, encrypter_pk: &ShareKey, paired_pk: &ShareKey) -> [u8; 96] {
    let mut aad = [0; 96];
    aad[..32].copy_from_slice(doc_id.as_bytes());
    aad[32..64].copy_from_slice(encrypter_pk.as_bytes());
    aad[64..].copy_from_slice(paired_pk.as_bytes());
    aad
}

/// Up to a few blocks of arbitrary sealed bytes, never shorter than a nonce
/// and a tag, so that every value has an encoding that decodes.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a, T> arbitrary::Arbitrary<'a> for EncryptedSecret<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut sealed = <[u8; SEAL_OVERHEAD]>::arbitrary(u)?.to_vec();
        sealed.extend(Vec::<u8>::arbitrary(u)?);
        Ok(EncryptedSecret {
            sealed,
            paired_pk: ShareKey::arbitrary(u)?,
            _plaintext_tag: PhantomData,
        })
    }
}

/// `sealed_len:bijou32 ‖ sealed ‖ paired_pk`.
impl<T> Encode for EncryptedSecret<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_bytes(&self.sealed, out);
        self.paired_pk.encode_into(out);
    }
}

impl<T> Decode for EncryptedSecret<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T> StreamDecode for EncryptedSecret<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (sealed, rest) = decode_bytes(bytes)?;
        if sealed.len() < SEAL_OVERHEAD {
            return Err(DecodeError::InvalidField("sealed"));
        }
        let (paired_pk, rest) = ShareKey::decode_next(rest)?;
        Ok((
            EncryptedSecret {
                sealed: sealed.to_vec(),
                paired_pk,
                _plaintext_tag: PhantomData,
            },
            rest,
        ))
    }
}

/// Seal a secret key for a tree node, paired with the given public key.
pub fn encrypt_secret(
    doc_id: TreeId,
    secret: ShareSecretKey,
    sk: &ShareSecretKey,
    paired_pk: &ShareKey,
) -> Result<EncryptedSecret<ShareSecretKey>, CgkaError> {
    encrypt_secret_with(&PairedKey::new(sk, paired_pk), doc_id, secret)
}

/// Seal a secret key under an already derived [`PairedKey`].
pub fn encrypt_secret_with(
    paired: &PairedKey,
    doc_id: TreeId,
    secret: ShareSecretKey,
) -> Result<EncryptedSecret<ShareSecretKey>, CgkaError> {
    let PairedKey {
        key,
        encrypter_pk,
        paired_pk,
    } = paired;
    let sealed = key
        .try_seal(
            &Vec::<u8>::from(&secret),
            &node_secret_aad(doc_id, encrypter_pk, paired_pk),
        )
        .map_err(CgkaError::Encryption)?;
    Ok(EncryptedSecret {
        sealed,
        paired_pk: *paired_pk,
        _plaintext_tag: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ed25519_dalek::SigningKey;

    type Content = EncryptedContent<Vec<u8>, [u8; 32]>;

    fn doc(n: u8) -> TreeId {
        TreeId::from(&SigningKey::from_bytes(&[n; 32]))
    }

    fn key(n: u8) -> SymmetricKey {
        SymmetricKey::from([n; 32])
    }

    fn encrypt(plaintext: &[u8]) -> Content {
        EncryptedContent::encrypt(
            &key(1),
            doc(1),
            [2; 32],
            PredecessorRefs::digest(&[[3; 32]]),
            [4; 32].into(),
            [5; 32].into(),
            plaintext,
        )
        .expect("a fresh key encrypts")
    }

    fn reencoded(content: &Content, edit: impl FnOnce(&mut Vec<u8>)) -> Content {
        let mut bytes = content.encode().into_bytes();
        edit(&mut bytes);
        Content::decode(&bytes).expect("the edit keeps the chunk lengths well formed")
    }

    /// The header: tag, version, content ref and three digests.
    const HEADER_LEN: usize = 3 + 1 + 32 + 3 * 32;

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
    fn the_encoding_starts_with_the_header() {
        let bytes = encrypt(b"hi").encode().into_bytes();
        assert_eq!(&bytes[..4], b"KHE\x00");
        assert_eq!(bytes.len(), HEADER_LEN + 2 + CHUNK_OVERHEAD);
    }

    #[test]
    fn the_wrong_key_or_document_does_not_decrypt() {
        let content = encrypt(b"secret");
        assert_eq!(
            content.try_decrypt(key(9), doc(1)),
            Err(ContentDecryptError::Decryption)
        );
        assert_eq!(
            content.try_decrypt(key(1), doc(9)),
            Err(ContentDecryptError::Decryption)
        );
    }

    /// Every header field is in every chunk's associated data.
    #[test]
    fn an_edited_header_does_not_decrypt() {
        let content = encrypt(b"secret");
        let fields = [
            ("content_ref", 4),
            ("pred_refs", 36),
            ("pcs_key_hash", 68),
            ("pcs_update_op", 100),
        ];
        for (field, at) in fields {
            let edited = reencoded(&content, |b| b[at] ^= 1);
            assert_eq!(
                edited.try_decrypt(key(1), doc(1)),
                Err(ContentDecryptError::Decryption),
                "{field} edited"
            );
        }
    }

    #[test]
    fn a_flipped_bit_in_any_chunk_does_not_decrypt() {
        let content = encrypt(&vec![7; 2 * CHUNK_LEN + 3]);
        for at in [
            HEADER_LEN,
            HEADER_LEN + FULL_CHUNK + 30,
            HEADER_LEN + 2 * FULL_CHUNK + 1,
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
        let chunk = |i: usize| HEADER_LEN + i * FULL_CHUNK..HEADER_LEN + (i + 1) * FULL_CHUNK;

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
        let keys = ChunkKeys::new(&key(1), doc(1), &content.header());
        let nonce = XNonce::from([9; NONCE_LEN]);
        let mut buf = b"forged".to_vec();
        keys.cipher
            .encrypt_in_place(&nonce, &keys.aad(0, true), &mut buf)
            .expect("encrypts");
        let forged = reencoded(&content, |b| {
            b.truncate(HEADER_LEN);
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
        let header = encrypt(b"").encode().into_bytes()[..HEADER_LEN].to_vec();
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
                let doc = TreeId::from(&SigningKey::from_bytes(doc_seed));
                let content: Content = EncryptedContent::encrypt(
                    &key(1),
                    doc,
                    *content_ref,
                    PredecessorRefs::digest(&[]),
                    [4; 32].into(),
                    [5; 32].into(),
                    plaintext,
                )
                .expect("encrypts");
                let read = Content::decode(content.encode().as_bytes()).expect("decodes");
                assert_eq!(read.try_decrypt(key(1), doc).as_ref(), Ok(plaintext));
            });
    }

    /// Pins the v1 derivations: a change here changes every ciphertext. The
    /// predecessor digest is BLAKE3 over `"KH" ‖ 'H' ‖ 0x00 ‖ count ‖ refs`.
    #[test]
    fn known_answer() {
        let content = encrypt(b"keyhive");
        assert_eq!(
            blake3::hash(content.encode().as_bytes()).to_hex().as_str(),
            "f6d0ac06eef9e9c5b9e3a43f48af0d4ac722594b2e2708d02311f4453cbe18e4"
        );
        assert_eq!(
            PredecessorRefs::digest(&[[3u8; 32]]).raw.to_hex().as_str(),
            "55450d263093c72d5367b8002c03f45eabcb4096e3e3344b3d628df936039a4e"
        );
    }

    fn share_sk(n: u8) -> ShareSecretKey {
        ShareSecretKey::force_from_bytes([n; 32])
    }

    /// The encrypter and the paired key's holder both open a node secret in
    /// the tree it was sealed in, and neither opens it in another.
    #[test]
    fn a_node_secret_opens_only_in_its_tree() {
        let (secret, encrypter, paired) = (share_sk(1), share_sk(2), share_sk(3));
        let sealed =
            encrypt_secret(doc(1), secret, &encrypter, &paired.share_key()).expect("seals");
        let plaintext = Vec::<u8>::from(&secret);
        for (tree, expected) in [
            (doc(1), Ok(plaintext)),
            (doc(2), Err(chacha20poly1305::Error)),
        ] {
            assert_eq!(sealed.try_encrypter_decrypt(tree, &encrypter), expected);
            assert_eq!(
                sealed.try_paired_decrypt(tree, &paired, &encrypter.share_key()),
                expected
            );
        }
    }

    /// A blob that authenticates under the right key and associated data,
    /// but whose nonce is not its synthetic nonce, is refused.
    #[test]
    fn a_node_secret_whose_nonce_is_not_synthetic_is_refused() {
        let (encrypter, paired) = (share_sk(2), share_sk(3));
        let aad = node_secret_aad(doc(1), &encrypter.share_key(), &paired.share_key());
        let nonce = [7; NONCE_LEN];
        let mut forged = Vec::<u8>::from(&share_sk(1));
        encrypter
            .derive_symmetric_key(&paired.share_key())
            .to_xchacha()
            .encrypt_in_place(&XNonce::from(nonce), &aad, &mut forged)
            .expect("encrypts");
        forged.splice(0..0, nonce);
        let mut bytes = Vec::new();
        encode_bytes(&forged, &mut bytes);
        paired.share_key().encode_into(&mut bytes);
        let secret = EncryptedSecret::<ShareSecretKey>::decode(&bytes).expect("decodes");
        assert_eq!(
            secret.try_encrypter_decrypt(doc(1), &encrypter),
            Err(chacha20poly1305::Error)
        );
    }
}
