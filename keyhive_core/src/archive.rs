//! Archive of [`Keyhive`][crate::keyhive::Keyhive].
//!
//! What a replica cannot recompute: its identity and key pairs, the
//! individuals it knows, the certificate set, every CGKA operation it holds,
//! each document's content heads and content keys, and the events still
//! waiting. A document's content keys are those of the content it has written
//! or read. CGKA groups are rebuilt from the operations on load, as a second
//! instance of an identity builds them; group membership is the certificate set.

use crate::{
    content::heads::ContentHeads,
    event::static_event::StaticEvent,
    principal::{
        active::archive::{key_pairs_len, ActiveArchive},
        document::{archive::DocumentArchive, id::DocumentId},
        individual::{id::IndividualId, IndividualState},
    },
};
use beekem::operation::CgkaOperation;
use keyhive_codec::{
    error::DecodeError,
    prefixed::{decode_len, decode_list, encode_len, encode_list},
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_content::reference::ContentRef;
use keyhive_crypto::{secret::write_secret, verified};
use keyline::certificate::Certificate;
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroizing;

/// What a [`Keyhive`][crate::keyhive::Keyhive] stores to be rebuilt.
///
/// It holds this replica's secret keys. To store it, use
/// [`Archive::encode_zeroizing`], not [`Encode::encode`], which leaves
/// unwiped copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive<T: ContentRef> {
    pub(crate) active: ActiveArchive,
    pub(crate) individuals: HashMap<IndividualId, IndividualState>,
    pub(crate) docs: HashMap<DocumentId, DocumentArchive<T>>,
    pub(crate) cgka_ops: Vec<verified::Signed<CgkaOperation>>,
    pub(crate) certificates: Vec<Certificate<ContentHeads<T>>>,
    pub(crate) pending_events: Vec<StaticEvent<T>>,
}

impl<T: ContentRef> Archive<T> {
    /// The magic bytes every archive starts with.
    pub const MAGIC: [u8; 4] = *b"KHIV";

    /// The format this build reads and writes. Only it decodes, so an archive
    /// in another format is refused rather than misread.
    pub const FORMAT: u8 = 4;

    /// Getter for the user that the [`Archive`] is for.
    pub fn id(&self) -> IndividualId {
        self.active.individual.id()
    }

    /// The archive's encoding, the same bytes as [`Encode`] gives, in a buffer
    /// that is wiped when dropped: it holds this replica's secret keys.
    ///
    /// The buffer never grows, so it leaves no copy of a key behind. Use this,
    /// not [`Encode::encode`], to store an archive.
    pub fn encode_zeroizing(&self) -> Zeroizing<Vec<u8>> {
        // Only the individuals and the statements are written outside the
        // wiped buffer: the key pairs and the documents (with their content
        // keys) must be written straight into it. The test
        // `no_secret_is_written_outside_the_wiped_buffer` checks that those
        // two sections hold no secret; it cannot see what this function does,
        // so keep any new secret-bearing section inside `write_secret`.
        let mut individuals = Vec::new();
        self.encode_individuals_into(&mut individuals);
        let mut statements = Vec::new();
        self.encode_statements_into(&mut statements);
        let len = Self::MAGIC.len()
            + 1
            + key_pairs_len(&self.active.key_pairs)
            + individuals.len()
            + self.docs_len()
            + statements.len();
        write_secret(len, |out| {
            self.encode_key_pairs_into(out);
            out.extend_from_slice(&individuals);
            self.encode_docs_into(out);
            out.extend_from_slice(&statements);
        })
    }

    /// The header and the key pairs. Secret.
    fn encode_key_pairs_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::MAGIC);
        out.push(Self::FORMAT);
        self.active.key_pairs.encode_into(out);
    }

    /// This replica's individual and the individuals it knows. Public.
    fn encode_individuals_into(&self, out: &mut Vec<u8>) {
        self.active.individual.encode_into(out);
        let individuals: BTreeMap<_, _> = self.individuals.values().map(|i| (i.id(), i)).collect();
        encode_len(individuals.len(), out);
        individuals.values().for_each(|i| i.encode_into(out));
    }

    /// The documents, with their content keys. Secret.
    fn encode_docs_into(&self, out: &mut Vec<u8>) {
        let docs: BTreeMap<_, _> = self.docs.iter().collect();
        encode_len(docs.len(), out);
        for (id, doc) in docs {
            id.encode_into(out);
            doc.encode_into(out);
        }
    }

    /// The length of [`Self::encode_docs_into`]'s output, found without
    /// writing a content key.
    fn docs_len(&self) -> usize {
        let mut count = Vec::new();
        encode_len(self.docs.len(), &mut count);
        count.len()
            + self
                .docs
                .iter()
                .map(|(id, doc)| id.encode().as_bytes().len() + doc.encoded_len())
                .sum::<usize>()
    }

    /// The CGKA operations, certificates and pending events. Public.
    fn encode_statements_into(&self, out: &mut Vec<u8>) {
        encode_by_key(&self.cgka_ops, |op| op.digest(), out);
        encode_by_key(&self.certificates, |cert| cert.id(), out);
        encode_by_key(&self.pending_events, |event| event.digest(), out);
    }
}

/// `"KHIV" ‖ format ‖ active ‖ individuals ‖ docs ‖ cgka_ops ‖ certificates ‖
/// pending_events`. Every collection is a count and then its elements in
/// ascending order of a key: an individual's id, a document's id, or a signed
/// statement's digest. A statement held twice is written once, so each archive
/// has one encoding. Individuals are stored without their ids, which their
/// prekey operations give.
///
/// `out` is not wiped and may reallocate, so this leaves copies of the secret
/// keys. To store an archive, use [`Archive::encode_zeroizing`].
impl<T: ContentRef> Encode for Archive<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.encode_key_pairs_into(out);
        self.encode_individuals_into(out);
        self.encode_docs_into(out);
        self.encode_statements_into(out);
    }
}

impl<T: ContentRef> Decode for Archive<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<T: ContentRef> StreamDecode for Archive<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let Some((magic, rest)) = bytes.split_first_chunk::<4>() else {
            return Err(DecodeError::UnexpectedEnd);
        };
        if *magic != Self::MAGIC {
            return Err(DecodeError::NotKeyhive);
        }
        let Some((&format, rest)) = rest.split_first() else {
            return Err(DecodeError::UnexpectedEnd);
        };
        if format != Self::FORMAT {
            return Err(DecodeError::UnsupportedVersion {
                kind: Self::MAGIC[2],
                version: format,
            });
        }
        let (active, rest) = ActiveArchive::decode_next(rest)?;
        let (individuals, rest) = decode_by_key(rest, IndividualState::id)?;
        let individuals = individuals.into_iter().map(|i| (i.id(), i)).collect();
        let (count, mut rest) = decode_len(rest)?;
        let mut docs = HashMap::new();
        let mut previous = None;
        for _ in 0..count {
            let (id, after) = DocumentId::decode_next(rest)?;
            let (doc, after) = DocumentArchive::decode_next(after)?;
            if previous.is_some_and(|p| p >= id) {
                return Err(DecodeError::UnsortedKeys);
            }
            previous = Some(id);
            docs.insert(id, doc);
            rest = after;
        }
        let (cgka_ops, rest) = decode_by_key(rest, |op: &verified::Signed<_>| op.digest())?;
        let (certificates, rest) = decode_by_key(rest, |cert: &Certificate<_>| cert.id())?;
        let (pending_events, rest) = decode_by_key(rest, |event: &StaticEvent<_>| event.digest())?;
        Ok((
            Archive {
                active,
                individuals,
                docs,
                cgka_ops,
                certificates,
                pending_events,
            },
            rest,
        ))
    }
}

/// A count, then `items` in ascending order of `key`, each key once.
fn encode_by_key<V: Encode, K: Ord>(items: &[V], key: impl Fn(&V) -> K, out: &mut Vec<u8>) {
    let by_key: BTreeMap<K, &V> = items.iter().rev().map(|item| (key(item), item)).collect();
    encode_list(by_key.values().copied(), out);
}

/// A counted list that must be strictly ascending by `key`.
fn decode_by_key<V: StreamDecode, K: Ord>(
    bytes: &[u8],
    key: impl Fn(&V) -> K,
) -> Result<(Vec<V>, &[u8]), DecodeError> {
    let (items, rest) = decode_list::<V>(bytes)?;
    if items.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return Err(DecodeError::UnsortedKeys);
    }
    Ok((items, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TestContext, TestResult};
    use keyline::power::Power::Read;

    /// The sections written outside the wiped buffer hold no secret: no share
    /// secret key and no content key appears in them.
    #[tokio::test]
    async fn no_secret_is_written_outside_the_wiped_buffer() -> TestResult<()> {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let bob = ctx.individual("bob").await?;
        let doc = ctx.doc(&alice, "doc").await?;
        alice.add_member(bob.id(), doc, Read).await?;
        ctx.encrypt(&alice, doc, b"one").await?;
        ctx.encrypt(&alice, doc, b"two").await?;
        let archive = alice.into_archive().await?;

        let secrets: Vec<&[u8]> = archive
            .active
            .key_pairs
            .values()
            .map(|sk| sk.as_slice())
            .chain(
                archive
                    .docs
                    .values()
                    .flat_map(|d| d.content_keys.values().map(|k| k.as_slice())),
            )
            .collect();
        assert!(
            archive.docs.values().any(|d| !d.content_keys.is_empty()),
            "precondition: the archive holds content keys"
        );

        let mut public = Vec::new();
        archive.encode_individuals_into(&mut public);
        archive.encode_statements_into(&mut public);
        for secret in secrets {
            assert!(
                !public.windows(secret.len()).any(|w| w == secret),
                "a secret was written outside the wiped buffer"
            );
        }
        Ok(())
    }

    /// The documents' length is found exactly, without writing them.
    #[tokio::test]
    async fn the_docs_length_is_exact() -> TestResult<()> {
        let mut ctx = TestContext::new().await;
        let alice = ctx.individual("alice").await?;
        let doc = ctx.doc(&alice, "doc").await?;
        ctx.encrypt(&alice, doc, b"one").await?;
        let archive = alice.into_archive().await?;

        let mut docs = Vec::new();
        archive.encode_docs_into(&mut docs);
        assert_eq!(archive.docs_len(), docs.len());
        Ok(())
    }

    /// Keys sort the items; a repeated key is written once, for its first
    /// item.
    #[test]
    fn items_are_written_in_key_order_each_key_once() {
        let mut out = Vec::new();
        encode_by_key(&[3u32, 1, 13, 2], |n| n % 10, &mut out);
        assert_eq!(decode_list::<u32>(&out), Ok((vec![1, 2, 3], &[][..])));
    }

    #[test]
    fn items_out_of_order_or_repeated_are_refused() {
        for items in [vec![2u32, 1], vec![1, 1]] {
            let mut out = Vec::new();
            encode_list(&items, &mut out);
            assert_eq!(
                decode_by_key(&out, |n: &u32| *n),
                Err(DecodeError::UnsortedKeys),
                "{items:?}"
            );
        }
    }
}
