//! A single user agent.

pub mod id;
pub mod op;
pub mod state;

use self::op::KeyOp;
use super::{agent::id::AgentId, document::id::DocumentId};
use crate::{
    contact_card::ContactCard,
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_more::Debug;
use ed25519_dalek::VerifyingKey;
use id::IndividualId;
use keyhive_crypto::{share_key::ShareKey, signed::VerificationError, verifiable::Verifiable};
use serde::{Deserialize, Serialize};
use state::PrekeyState;
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;
use tracing::instrument;

#[cfg(any(feature = "test_utils", test))]
use future_form::FutureForm;
#[cfg(any(feature = "test_utils", test))]
use keyhive_crypto::{signed::SigningError, signer::async_signer::AsyncSigner};

#[cfg(any(feature = "test_utils", test))]
use std::num::NonZeroUsize;

/// Single agents with no internal membership.
///
/// `Individual`s can be thought of as the terminal agents. They represent
/// keys that may sign ops, be delegated capabilities to
/// [`Document`][super::document::Document]s and [`Group`][super::group::Group]s.
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct Individual {
    /// The public key identifier.
    pub(crate) id: IndividualId,

    /// [`ShareKey`] pre-keys.
    ///
    /// Prekeys are used to invite this `Individual` to [`Document`] read access trees.
    /// The core idea is that the invited `Individual` is offline, but needs to be added to
    /// the encryption tree for a particular [`Document`]. They publish a set of public keys
    /// in advance. The inviter can then deterministically select one, and use it as the
    /// initial key for the invitee's BeeKEM entry. The next time they're online, the invitee
    /// should then remove the prekey from their public set and rotate the BeeKEM key on the [`Document`].
    ///
    /// The use of unique prekeys for each new [`Document`] invite isolates each [`Document`] from
    /// the compromise of one prekey affecting the security of other [`Document`]s. Since we operate
    /// in a fully concurrent context with causal consistency, we cannot guarantee that a prekey will
    /// not be reused in multiple [`Document`]s, but we can tune the probability of this happening.
    ///
    /// [`Document`]: super::document::Document
    pub(crate) prekeys: HashSet<ShareKey>,

    /// The state used to materialize `prekeys`.
    pub(crate) prekey_state: PrekeyState,
}

impl Individual {
    #[instrument]
    pub fn new(initial_op: KeyOp) -> Self {
        let id = IndividualId(initial_op.verifying_key().into());
        let prekey_state = PrekeyState::new(initial_op);

        Self {
            id,
            prekeys: prekey_state.build(),
            prekey_state,
        }
    }

    #[cfg(any(feature = "test_utils", test))]
    #[instrument(skip_all)]
    pub async fn generate<F: FutureForm, R: rand::CryptoRng + rand::RngCore, S: AsyncSigner<F>>(
        signer: &S,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let prekey_state =
            PrekeyState::generate::<F, _, _>(signer, NonZeroUsize::new(8).unwrap(), csprng).await?;

        Ok(Self {
            id: IndividualId(signer.verifying_key().into()),
            prekeys: prekey_state.build(),
            prekey_state,
        })
    }

    pub fn contact_card(&self) -> ContactCard {
        let op = self.prekey_state.ops().0.iter().next().unwrap().1;
        ContactCard::from(Arc::unwrap_or_clone(op.clone()))
    }

    pub fn id(&self) -> IndividualId {
        self.id
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id)
    }

    #[instrument(skip(self), fields(indie_id = %self.id))]
    pub fn receive_prekey_op(&mut self, op: op::KeyOp) -> Result<(), ReceivePrekeyOpError> {
        if op.verifying_key() != self.id.verifying_key() {
            return Err(ReceivePrekeyOpError::IncorrectSigner);
        }

        self.prekey_state.insert_op(op)?;
        self.prekeys = self.prekey_state.build();
        Ok(())
    }

    #[instrument(skip(self), fields(indie_id = %self.id))]
    pub fn pick_prekey(&self, doc_id: DocumentId) -> Result<&ShareKey, MissingPrekeys> {
        let mut bytes: Vec<u8> = self.id.to_bytes().to_vec();
        bytes.extend_from_slice(&doc_id.to_bytes());

        let prekeys_len = self.prekeys.len();
        if prekeys_len == 0 {
            // An individual whose Add/rotate prekey ops have not been ingested yet has nothing
            // to pick from. That is a recoverable race — the ops arrive by sync — so it is an
            // error the caller can retry, not a panic that takes the whole process down.
            return Err(MissingPrekeys::NoPublishedPrekey(Box::new(self.id)));
        }
        let idx = pseudorandom_in_range(bytes.as_slice(), prekeys_len);

        self.prekeys
            .iter()
            .nth(idx)
            .ok_or(MissingPrekeys::NoPublishedPrekey(Box::new(self.id)))
    }

    pub fn prekey_ops(&self) -> &CaMap<KeyOp> {
        self.prekey_state.ops()
    }

    /// The live prekeys, after applying every op in the prekey state.
    ///
    /// A key that has been rotated away is absent, and the iteration order is not
    /// meaningful. Use [`Individual::prekey_ops`] for the log that produced them.
    pub fn prekeys(&self) -> &HashSet<ShareKey> {
        &self.prekeys
    }

    #[instrument]
    pub fn rebuild(&mut self) {
        self.prekeys = self.prekey_state.build();
    }
}

impl std::hash::Hash for Individual {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.prekey_state.hash(state);
        for pk in self.prekeys.iter() {
            pk.hash(state);
        }
    }
}

impl PartialOrd for Individual {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Individual {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.to_bytes().cmp(&other.id.to_bytes())
    }
}

impl Verifiable for Individual {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.verifying_key()
    }
}

impl Fork for Individual {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for Individual {
    fn merge(&mut self, fork: Self::Forked) {
        self.prekey_state.merge(fork.prekey_state);
        self.rebuild()
    }
}

#[derive(Debug, Error)]
pub enum ReceivePrekeyOpError {
    #[error("The op was not signed by the expected individual.")]
    IncorrectSigner,

    #[error(transparent)]
    VerificationError(#[from] VerificationError),
}

/// Errors from selecting a published prekey.
#[derive(Debug, Error)]
pub enum MissingPrekeys {
    /// The individual has published no prekey to select from. The id is boxed because
    /// [`IndividualId`] carries a decompressed curve point, which would otherwise inflate
    /// every error enum this variant is embedded in (clippy's `result_large_err`).
    #[error("individual {0} has published no prekey to select from")]
    NoPublishedPrekey(Box<IndividualId>),
}

fn clamp(bytes: [u8; 8], offset_bits: u8) -> usize {
    let bound = u64::from_be_bytes(bytes)
        .checked_shl(offset_bits as u32)
        .unwrap_or(0);

    usize::from_be(bound as usize)
}

fn pseudorandom_in_range(seed: &[u8], max: usize) -> usize {
    let digits: u8 = max
        .checked_ilog2()
        .unwrap_or(0)
        .try_into()
        .expect("usize has at most 64 bits (< 256)");

    let shiftsize: u8 = 64 - digits;

    let mut hash_stream = blake3::Hasher::new().update(seed).finalize_xof();
    let mut buf = [0; 8]; // usize max
    let mut idx = None;

    // NOTE this strategy looks odd at first, but it's an established way to
    // avoid the biases that you get when sampling a (P)RNG and using a modulous
    // to clamp to a range. Because the range (idx in our case) is likely not
    // the same size as the RNG, a modulous will bias towards the lower end of the range.
    // We use resampling here instead is a way to avoid this bias.
    //
    // Naively reampling from `usize` would be very inefficient when the
    // range is small because it's so unlikely to get a random number in that range.
    // to fix this, we first truncate the random number to the closest power of 2,
    // which gives us a >=50% chance of getting a number in the range.
    while idx.is_none() {
        hash_stream.fill(&mut buf);
        let raw_idx: usize = clamp(buf, shiftsize);
        if raw_idx <= max {
            idx = Some(raw_idx)
        }
    }

    idx.expect("index to be Some due to the check above")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
    use keyhive_crypto::signer::memory::MemorySigner;

    #[test]
    fn test_to_bytes() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);
        let op = sk.try_sign_sync(AddKeyOp::generate(&mut csprng)).unwrap();
        let individual: Individual = Individual::new(Arc::new(op).into());
        assert_eq!(individual.id.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn test_clamp_sequence() {
        test_utils::init_logging();

        let a = clamp([0xFF; 8], 0);
        let b = clamp([0xFF; 8], 1);
        let c = clamp([0xFF; 8], 8);
        let d = clamp([0xFF; 8], 16);
        let e = clamp([0xFF; 8], 32);
        let f = clamp([0xFF; 8], 48);
        let g = clamp([0xFF; 8], 64);

        assert_eq!(a, usize::MAX);
        assert!(a > b);
        assert!(b > c);
        assert!(c > d);
        assert!(d > e);
        assert!(e > f);
        assert!(f > g);
        assert_eq!(g, 0);
    }

    #[test]
    fn test_clamp_keeps_in_range() {
        test_utils::init_logging();

        let x = clamp([0xFF; 8], 48);
        assert!(x <= 2usize.pow(64 - 48));
        assert_eq!(x, 65535);
    }

    #[test]
    fn test_clamp_keeps_in_range_2() {
        test_utils::init_logging();

        let buf: [u8; 8] = rand::random();
        let x = clamp(buf, 48);
        assert!(x <= 2usize.pow(64 - 48));
    }

    #[test]
    fn test_pseudorandom_in_range() {
        test_utils::init_logging();

        let arr = 0..39; // Not byte aligned
        let seed: [u8; 32] = rand::random();
        let index = pseudorandom_in_range(&seed, arr.len());
        assert!(index < arr.len());
    }

    #[test]
    fn test_pseudorandom_generates_random_values() {
        test_utils::init_logging();

        let arr = 0..39; // Not byte aligned

        let seed1: [u8; 32] = [0u8; 32];
        let seed2: [u8; 32] = [1u8; 32];
        let seed3: [u8; 32] = [2u8; 32];

        let index1 = pseudorandom_in_range(&seed1, arr.len());
        let index2 = pseudorandom_in_range(&seed2, arr.len());
        let index3 = pseudorandom_in_range(&seed3, arr.len());

        assert_ne!(index1, index2);
        assert_ne!(index1, index3);
        assert_ne!(index2, index3);
    }

    #[test]
    fn test_pseudorandom_generates_stays_in_range() {
        test_utils::init_logging();

        let seed1: [u8; 32] = rand::random();
        let seed2: [u8; 32] = rand::random();

        let index1 = pseudorandom_in_range(&seed1, 0);
        let index2 = pseudorandom_in_range(&seed2, 0);

        assert_eq!(index1, 0);
        assert_eq!(index1, index2);
    }

    /// Regression: a stale rotation cycle (rotate A→B then B→A) must never
    /// empty the published prekey set. `pick_prekey` reports [`MissingPrekeys`]
    /// on an empty set, and the documented invariant is that an individual
    /// always keeps at least one published prekey.
    #[test]
    fn rotation_cycle_keeps_prekeys_nonempty() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);

        // Publish a single prekey.
        let k1 = AddKeyOp::generate(&mut csprng);
        let add_op = sk.try_sign_sync(k1.clone()).unwrap();
        let mut individual = Individual::new(Arc::new(add_op).into());
        assert_eq!(individual.prekeys.len(), 1);

        // Rotate k1 -> k2.
        let k2 = ShareKey::generate(&mut csprng);
        let rot1 = sk
            .try_sign_sync(RotateKeyOp {
                old: k1.share_key,
                new: k2,
            })
            .unwrap();
        individual
            .receive_prekey_op(KeyOp::Rotate(Arc::new(rot1)))
            .unwrap();
        assert_eq!(individual.prekeys.len(), 1);

        // Rotate k2 -> k1: the rotation cycle. The published set must stay
        // non-empty and pick_prekey must not panic.
        let rot2 = sk
            .try_sign_sync(RotateKeyOp {
                old: k2,
                new: k1.share_key,
            })
            .unwrap();
        individual
            .receive_prekey_op(KeyOp::Rotate(Arc::new(rot2)))
            .unwrap();
        assert!(
            !individual.prekeys.is_empty(),
            "rotation cycle must not empty the published prekey set"
        );
        assert!(
            individual
                .pick_prekey(DocumentId::generate(&mut csprng))
                .is_ok(),
            "a non-empty published prekey set still selects a prekey"
        );
    }

    /// Regression: a prekey state whose ops contain no `Add` must still serialize.
    ///
    /// `Keyhive::contact_card` rotates a prekey as it generates the card, and
    /// `Individual::from(card)` builds the receiving individual from that op alone, so an
    /// individual's ops can hold a rotation and nothing else. `reachable_prekey_ops_for_all_agents`
    /// advertises individuals by running their ops through `KeyOp::topsort`, so a rotation-only map
    /// that topsorts to nothing means no peer can ever obtain that individual's prekeys.
    #[test]
    fn rotate_only_prekey_state_topsorts_to_its_rotation() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);

        let k1 = AddKeyOp::generate(&mut csprng);
        let k2 = ShareKey::generate(&mut csprng);
        let rot = sk
            .try_sign_sync(RotateKeyOp {
                old: k1.share_key,
                new: k2,
            })
            .unwrap();

        // Exactly what `Individual::from(&contact_card)` does with a rotated card.
        let individual = Individual::new(KeyOp::Rotate(Arc::new(rot)));
        assert_eq!(individual.prekey_ops().len(), 1, "the state holds the rotation",);
        assert!(
            !individual.prekeys.is_empty(),
            "the published key set is non-empty, so local selection works"
        );
        assert_eq!(
            KeyOp::topsort(individual.prekey_ops()).len(),
            1,
            "a rotation-only prekey state must serialize to its rotation; an empty topsort \
             means no peer can ever obtain this individual's prekeys"
        );
    }

    /// Regression: a rotation cycle reached from a seeded head must terminate, and must not emit
    /// one prekey twice.
    ///
    /// `KeyOp::topsort` walks `rotate_key_ops` by following each op's produced key, so a cycle
    /// (`k0→k1` then `k1→k0`) makes the walk revisit ops it has already followed. Without the
    /// `emitted.insert(head.new_key())` dedup, each rotation re-enqueues the other and
    /// `while let Some(head) = heads.pop()` never drains.
    ///
    /// A failure here HANGS rather than failing an assertion: the signal is nextest's per-test
    /// timeout, not a panic. Do not read a timeout on this test as load flakiness.
    ///
    /// The dedup keys on the op's *produced key* rather than on the op, so the rotation that
    /// closes a cycle is dropped from the output: `k0` was already emitted by the add. The
    /// assertion records that, so the drop is visible rather than read as a missing op.
    #[test]
    fn chained_prekey_rotation_cycle_terminates_and_emits_no_op_twice() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);

        let k0 = AddKeyOp::generate(&mut csprng);
        let k1 = ShareKey::generate(&mut csprng);

        let add = sk.try_sign_sync(k0.clone()).unwrap();
        let rot_out = sk
            .try_sign_sync(RotateKeyOp {
                old: k0.share_key,
                new: k1,
            })
            .unwrap();
        let rot_back = sk
            .try_sign_sync(RotateKeyOp {
                old: k1,
                new: k0.share_key,
            })
            .unwrap();

        let ops = CaMap::from_iter_direct([
            Arc::new(KeyOp::Add(Arc::new(add))),
            Arc::new(KeyOp::Rotate(Arc::new(rot_out))),
            Arc::new(KeyOp::Rotate(Arc::new(rot_back))),
        ]);

        let topsorted = KeyOp::topsort(&ops);

        assert_eq!(
            topsorted.len(),
            2,
            "the walk terminates: the add and the rotation it feeds are emitted, and the \
             rotation closing the cycle is dropped because its produced key was already emitted"
        );
        let emitted: HashSet<ShareKey> = topsorted.iter().map(|op| *op.new_key()).collect();
        assert_eq!(
            emitted,
            HashSet::from([k0.share_key, k1]),
            "the add's key and the rotation's key are both emitted"
        );
        assert_eq!(emitted.len(), topsorted.len(), "no prekey is emitted twice");
    }

    /// Regression: a chained rotation must not be seeded as well as walked.
    ///
    /// The seeding loop treats a rotation as a head only when no op in the map produces the key it
    /// consumed. A rotation-only state is routine — the add that created the consumed key may have
    /// been pruned, and `Individual::from(card)` builds an individual from a rotation alone — so
    /// a rotation-only *chain* is a shape that must serialize, and its order must follow the keys.
    ///
    /// Without the `produced` check both rotations are seeded and the LIFO `heads.pop()` can emit
    /// the chain in reverse, so a peer would replay a rotation before the key it consumed. The
    /// length stays 2 in that variant only because the emitted dedup drops the second visit, which
    /// is why the order is asserted here rather than the length alone.
    #[test]
    fn topsort_does_not_seed_a_rotation_whose_consumed_key_is_produced() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);

        let k0 = ShareKey::generate(&mut csprng);
        let k1 = ShareKey::generate(&mut csprng);
        let k2 = ShareKey::generate(&mut csprng);

        let rot1 = sk.try_sign_sync(RotateKeyOp { old: k0, new: k1 }).unwrap();
        let rot2 = sk.try_sign_sync(RotateKeyOp { old: k1, new: k2 }).unwrap();

        // `k0` is absent from the map (its add was pruned), so only `rot1` is a head.
        let ops = CaMap::from_iter_direct([
            Arc::new(KeyOp::Rotate(Arc::new(rot1))),
            Arc::new(KeyOp::Rotate(Arc::new(rot2))),
        ]);

        let topsorted = KeyOp::topsort(&ops);

        assert_eq!(topsorted.len(), 2, "both rotations of the chain serialize");
        assert_eq!(
            *topsorted[0].new_key(),
            k1,
            "the rotation whose consumed key is produced by no op is emitted first"
        );
        assert_eq!(
            *topsorted[1].new_key(),
            k2,
            "the rotation consuming the first one's key follows it"
        );
    }

    /// Regression: a rotation-only state whose rotations form a cycle still serializes.
    ///
    /// With no `Add` in the map, every consumed key can be produced by another rotation — `k1 → k2`
    /// together with `k2 → k1` — so the "consumed key is produced by no op" seeding rule finds no
    /// head at all and `topsort` returns zero ops for a state that holds two. That is the same
    /// outcome the rotation-only case above exists to prevent (no peer can obtain this individual's
    /// prekeys, so the next grant naming it fails selection), and it is reachable once the `Add`
    /// that created the consumed key has been pruned.
    ///
    /// A cycle has no causal entry point, so any of its rotations may start the walk. This asserts
    /// the emitted key *set* is complete and holds each op once, not the order the walk chose.
    #[test]
    fn rotation_only_cycle_topsorts_to_every_rotation() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);

        let k1 = ShareKey::generate(&mut csprng);
        let k2 = ShareKey::generate(&mut csprng);

        let rot_forward = sk.try_sign_sync(RotateKeyOp { old: k1, new: k2 }).unwrap();
        let rot_back = sk.try_sign_sync(RotateKeyOp { old: k2, new: k1 }).unwrap();

        // No `Add`: `k1` is produced only by the rotation that consumes `k2`, and vice versa.
        let ops = CaMap::from_iter_direct([
            Arc::new(KeyOp::Rotate(Arc::new(rot_forward))),
            Arc::new(KeyOp::Rotate(Arc::new(rot_back))),
        ]);

        let topsorted = KeyOp::topsort(&ops);

        assert_eq!(
            topsorted.len(),
            2,
            "both rotations of the cycle serialize; an empty topsort means no peer can obtain \
             this individual's prekeys"
        );
        let emitted: HashSet<ShareKey> = topsorted.iter().map(|op| *op.new_key()).collect();
        assert_eq!(
            emitted,
            HashSet::from([k1, k2]),
            "every key in the cycle is advertised"
        );
        assert_eq!(emitted.len(), topsorted.len(), "no prekey is emitted twice");
    }

    /// Regression: an individual whose prekey ops have not been ingested yet carries an empty
    /// published set (a state a deserialized archive can represent). Selecting a prekey must
    /// report that as a typed error — the caller retries once the ops land — instead of
    /// panicking with "index to be in range".
    #[test]
    fn empty_prekey_set_reports_missing_prekeys() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);
        let add_op = AddKeyOp::generate(&mut csprng);
        let mut individual = Individual::new(Arc::new(sk.try_sign_sync(add_op).unwrap()).into());
        assert_eq!(individual.prekeys.len(), 1);

        individual.prekeys.clear();
        individual.prekey_state = PrekeyState::empty_for_tests();

        let error = individual
            .pick_prekey(DocumentId::generate(&mut csprng))
            .expect_err("an empty published prekey set has nothing to pick");
        assert!(
            matches!(&error, MissingPrekeys::NoPublishedPrekey(id) if **id == individual.id()),
            "the error names the individual that published no prekey: {error:?}"
        );
    }
}
