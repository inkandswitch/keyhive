//! An individual: a single key, with no members.

pub mod id;
pub mod op;
pub mod state;

use self::op::KeyOp;
use super::document::id::DocumentId;
use crate::{
    contact_card::ContactCard,
    content::heads::ContentHeads,
    keyhive::Keyhive,
    listener::membership::MembershipListener,
    store::ciphertext::{CiphertextStore, CiphertextStoreExt},
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_more::Debug;
use ed25519_dalek::VerifyingKey;
use future_form::FutureForm;
use id::IndividualId;
use keyhive_crypto::{
    content::reference::ContentRef, identifier::Identifier, share_key::ShareKey,
    signer::async_signer::AsyncSigner, verifiable::Verifiable, verified::VerifyError,
};
use keyline::contract::Keyline;
use serde::{Deserialize, Serialize};
use state::PrekeyState;
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;
use tracing::instrument;

#[cfg(any(feature = "test_utils", test))]
use keyhive_crypto::verified::SignError;

use rand::{CryptoRng, RngCore};
#[cfg(any(feature = "test_utils", test))]
use std::num::NonZeroUsize;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

/// A single key, with no members.
///
/// `IndividualState`s can be thought of as the terminal principals. They represent
/// keys that may sign ops, be delegated capabilities to
/// [`DocumentState`][super::document::DocumentState]s and [`Group`][super::group::Group]s.
///
/// Serialized as its prekey operations alone: the id and the live prekeys
/// follow from them, and deserializing checks that every operation verifies
/// and has the same issuer.
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(PartialEq, Eq)]
#[serde(into = "PrekeyState", try_from = "PrekeyState")]
pub struct IndividualState {
    /// The public key identifier.
    pub(crate) id: IndividualId,

    /// [`ShareKey`] pre-keys.
    ///
    /// Prekeys are used to invite this `IndividualState` to the CGKA groups of documents it can
    /// read. The core idea is that the invited `IndividualState` is offline, but needs to be added
    /// to the CGKA group for a particular [`DocumentState`]. They publish a set of public keys
    /// in advance. The inviter can then deterministically select one, and use it as the
    /// initial key for the invitee in the CGKA group. The next time they're online, the invitee
    /// should then remove the prekey from their public set and rotate their key in the CGKA group.
    ///
    /// The use of unique prekeys for each new [`DocumentState`] invite isolates each [`DocumentState`] from
    /// the compromise of one prekey affecting the security of other [`DocumentState`]s. Since we operate
    /// in a fully concurrent context with causal consistency, we cannot guarantee that a prekey will
    /// not be reused in multiple [`DocumentState`]s, but we can tune the probability of this happening.
    ///
    /// [`DocumentState`]: super::document::DocumentState
    pub(crate) prekeys: HashSet<ShareKey>,

    /// The state used to materialize `prekeys`.
    pub(crate) prekey_state: PrekeyState,
}

impl IndividualState {
    #[instrument]
    pub fn new(initial_op: KeyOp) -> Self {
        let id = IndividualId::from(initial_op.issuer());
        let prekey_state = PrekeyState::new(initial_op);

        Self {
            id,
            prekeys: prekey_state.build(),
            prekey_state,
        }
    }

    #[cfg(any(feature = "test_utils", test))]
    #[instrument(skip_all)]
    pub async fn generate<F: FutureForm, R: CryptoRng + RngCore, S: AsyncSigner<F>>(
        signer: &S,
        csprng: &mut R,
    ) -> Result<Self, SignError> {
        let prekey_state =
            PrekeyState::generate::<F, _, _>(signer, NonZeroUsize::new(8).unwrap(), csprng).await?;

        Ok(Self {
            id: IndividualId::try_from(signer.verifying_key())?,
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

    #[instrument(skip(self), fields(indie_id = %self.id))]
    pub fn receive_prekey_op(&mut self, op: op::KeyOp) -> Result<(), ReceivePrekeyOpError> {
        if op.issuer() != Identifier::from(self.id) {
            return Err(ReceivePrekeyOpError::IncorrectSigner);
        }

        self.prekey_state.insert_op(op);
        self.prekeys = self.prekey_state.build();
        Ok(())
    }

    /// Pick a prekey for this individual for `doc_id`, or `None` if it has no
    /// live prekeys (rotations can retire every one).
    ///
    /// Chosen from the live prekeys in sorted order by a hash of this
    /// individual and the document: every replica holding the same prekeys
    /// picks the same one, and different documents spread across them.
    #[instrument(skip(self), fields(indie_id = %self.id))]
    pub fn pick_prekey(&self, doc_id: DocumentId) -> Option<&ShareKey> {
        let mut seed: Vec<u8> = self.id.to_bytes().to_vec();
        seed.extend_from_slice(&doc_id.to_bytes());

        let mut sorted: Vec<&ShareKey> = self.prekeys.iter().collect();
        sorted.sort_unstable();
        uniform_index(&seed, sorted.len()).map(|i| sorted[i])
    }

    pub fn prekey_ops(&self) -> &CaMap<KeyOp> {
        self.prekey_state.ops()
    }

    /// The live prekeys, after applying every op in the prekey state.
    ///
    /// A key that has been rotated away is absent, and the iteration order is not
    /// meaningful. Use [`IndividualState::prekey_ops`] for the log that produced them.
    pub fn prekeys(&self) -> &HashSet<ShareKey> {
        &self.prekeys
    }

    #[instrument]
    pub fn rebuild(&mut self) {
        self.prekeys = self.prekey_state.build();
    }
}

impl From<IndividualState> for PrekeyState {
    fn from(individual: IndividualState) -> Self {
        individual.prekey_state
    }
}

impl TryFrom<PrekeyState> for IndividualState {
    type Error = InvalidPrekeyState;

    fn try_from(prekey_state: PrekeyState) -> Result<Self, Self::Error> {
        let mut issuers = prekey_state.ops().values().map(|op| op.issuer());
        let id = issuers.next().ok_or(InvalidPrekeyState::Empty)?;
        if issuers.any(|issuer| issuer != id) {
            return Err(InvalidPrekeyState::MixedIssuers);
        }
        Ok(Self {
            id: IndividualId::from(id),
            prekeys: prekey_state.build(),
            prekey_state,
        })
    }
}

/// Why prekey operations do not make an [`IndividualState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InvalidPrekeyState {
    /// There are none.
    #[error("an individual needs at least one prekey operation")]
    Empty,

    /// They were signed by more than one key.
    #[error("prekey operations from more than one issuer")]
    MixedIssuers,
}

impl Hash for IndividualState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.prekey_state.hash(state);
        for pk in self.prekeys.iter() {
            pk.hash(state);
        }
    }
}

impl PartialOrd for IndividualState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IndividualState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.to_bytes().cmp(&other.id.to_bytes())
    }
}

impl Verifiable for IndividualState {
    fn verifying_key(&self) -> VerifyingKey {
        self.id.verifying_key()
    }
}

impl Fork for IndividualState {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

/// Merges only the same individual's state: another individual's prekey
/// operations are ignored, so an individual never holds two issuers' ops.
impl Merge for IndividualState {
    fn merge(&mut self, fork: Self::Forked) {
        if fork.id != self.id {
            tracing::warn!(ours = %self.id, theirs = %fork.id, "not merging another individual's prekeys");
            return;
        }
        self.prekey_state.merge(fork.prekey_state);
        self.rebuild()
    }
}

/// An individual, as a transient handle over the keyhive: one whose prekeys
/// this replica holds.
#[derive(Debug, Clone)]
pub struct Individual<KH> {
    keyhive: KH,
    id: IndividualId,
}

impl<KH> Individual<KH> {
    pub(crate) fn new(keyhive: KH, id: IndividualId) -> Self {
        Individual { keyhive, id }
    }

    /// The keyhive this handle reads through.
    pub fn keyhive(&self) -> &KH {
        &self.keyhive
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn individual_id(&self) -> IndividualId {
        self.id
    }
}

impl<F, S, T, P, C, L, R, K> Individual<Keyhive<F, S, T, P, C, L, R, K>>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: for<'de> Deserialize<'de>,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: CryptoRng + RngCore,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    K::Error: Send + Sync + 'static,
{
    /// Pick a prekey for this individual for `doc`, or `None` if it has no
    /// live prekeys.
    pub async fn pick_prekey(&self, doc: DocumentId) -> Option<ShareKey> {
        if self.id == self.keyhive.id() {
            return self.keyhive.active().pick_prekey(doc).await;
        }
        let state = self.keyhive.individual_state(self.id).await?;
        let prekey = state.lock().await.pick_prekey(doc).copied();
        prekey
    }

    /// The prekeys this replica holds for this individual.
    pub async fn prekeys(&self) -> HashSet<ShareKey> {
        match self.keyhive.individual_state(self.id).await {
            Some(state) => state.lock().await.prekeys().clone(),
            None => HashSet::new(),
        }
    }

    /// Every prekey operation this replica holds for this individual.
    pub async fn prekey_ops(&self) -> CaMap<KeyOp> {
        match self.keyhive.individual_state(self.id).await {
            Some(state) => state.lock().await.prekey_ops().clone(),
            None => CaMap::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ReceivePrekeyOpError {
    #[error("The op was not signed by the expected individual.")]
    IncorrectSigner,

    /// It did not decode canonically, or its signature did not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// An index below `len`, uniform and fixed by `seed`; `None` when `len` is 0.
///
/// Rejection sampling over BLAKE3's output stream: a draw at or above the
/// largest multiple of `len` that fits in a `u64` is redrawn, so reducing
/// modulo `len` has no bias.
fn uniform_index(seed: &[u8], len: usize) -> Option<usize> {
    let n = u64::try_from(len).ok().filter(|&n| n > 0)?;
    let limit = u64::MAX - u64::MAX % n;
    let mut stream = blake3::Hasher::new_derive_key("keyhive prekey selection v1")
        .update(seed)
        .finalize_xof();
    let mut buf = [0; 8];
    loop {
        stream.fill(&mut buf);
        let draw = u64::from_le_bytes(buf);
        if draw < limit {
            return Some(usize::try_from(draw % n).expect("below `len`, a `usize`"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
    use keyhive_crypto::{
        share_key::ShareSecretKey, signer::memory::MemorySigner, verified::Verified,
    };
    use std::collections::BTreeSet;

    fn add(signer: &MemorySigner, share_key: ShareKey) -> KeyOp {
        KeyOp::Add(Verified::sign_sync(&AddKeyOp { share_key }, signer).expect("signs"))
    }

    fn rotate(signer: &MemorySigner, old: ShareKey, new: ShareKey) -> KeyOp {
        KeyOp::Rotate(Verified::sign_sync(&RotateKeyOp { old, new }, signer).expect("signs"))
    }

    fn key() -> ShareKey {
        ShareSecretKey::generate(&mut rand::thread_rng()).share_key()
    }

    /// An individual with `n` live prekeys, its ops inserted in shuffled order.
    fn with_prekeys(signer: &MemorySigner, n: usize) -> IndividualState {
        use rand::seq::SliceRandom;
        let mut ops: Vec<KeyOp> = (0..n).map(|_| add(signer, key())).collect();
        ops.shuffle(&mut rand::thread_rng());
        let mut ops = ops.into_iter();
        let mut individual = IndividualState::new(ops.next().expect("at least one"));
        for op in ops {
            individual.receive_prekey_op(op).expect("same issuer");
        }
        individual
    }

    fn doc() -> DocumentId {
        DocumentId(
            Identifier::try_from(MemorySigner::generate(&mut rand::thread_rng()).verifying_key())
                .expect("a generated key is a valid id"),
        )
    }

    #[test]
    fn test_to_bytes() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = MemorySigner::generate(&mut csprng);
        let op = Verified::sign_sync(&AddKeyOp::generate(&mut csprng), &sk).unwrap();
        let individual: IndividualState = IndividualState::new(KeyOp::Add(op));
        assert_eq!(individual.id.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn a_uniform_index_is_below_its_bound() {
        bolero::check!()
            .with_type::<(Vec<u8>, u16)>()
            .for_each(|(seed, len)| {
                let len = usize::from(*len);
                match uniform_index(seed, len) {
                    None => assert_eq!(len, 0),
                    Some(i) => assert!(i < len, "{i} < {len}"),
                }
            });
    }

    /// Every count of prekeys, including powers of two, picks one of them.
    #[test]
    fn a_prekey_is_picked_for_every_count() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        for n in 1..=33 {
            let individual = with_prekeys(&signer, n);
            for _ in 0..16 {
                let picked = individual.pick_prekey(doc()).expect("it has prekeys");
                assert!(individual.prekeys().contains(picked));
            }
        }
    }

    /// The pick depends on the prekeys and the document, not on the order the
    /// ops arrived in, so replicas holding the same prekeys agree.
    #[test]
    fn replicas_with_the_same_prekeys_pick_the_same_one() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let keys: Vec<ShareKey> = (0..12).map(|_| key()).collect();
        let build = |order: &[usize]| {
            let mut ops = order.iter().map(|&i| add(&signer, keys[i]));
            let mut individual = IndividualState::new(ops.next().expect("nonempty"));
            for op in ops {
                individual.receive_prekey_op(op).expect("same issuer");
            }
            individual
        };
        let forward = build(&(0..12).collect::<Vec<_>>());
        let backward = build(&(0..12).rev().collect::<Vec<_>>());
        for _ in 0..32 {
            let d = doc();
            assert_eq!(forward.pick_prekey(d), backward.pick_prekey(d));
        }
    }

    /// Different documents spread across the prekeys.
    #[test]
    fn documents_spread_across_prekeys() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let individual = with_prekeys(&signer, 8);
        let picked: BTreeSet<ShareKey> = (0..200)
            .map(|_| *individual.pick_prekey(doc()).expect("it has prekeys"))
            .collect();
        // Missing one of 8 keys in 200 uniform picks has probability below 1e-10.
        assert_eq!(picked.len(), 8);
    }

    /// Merging the same individual's state adds its prekeys; another
    /// individual's state is ignored, so no individual holds two issuers' ops.
    #[test]
    fn an_individual_merges_only_its_own_state() {
        let alice = MemorySigner::generate(&mut rand::thread_rng());
        let mallory = MemorySigner::generate(&mut rand::thread_rng());
        let (a, b) = (key(), key());
        let mut ours = IndividualState::new(add(&alice, a));

        ours.merge(IndividualState::new(add(&alice, b)));
        assert_eq!(ours.prekeys(), &HashSet::from([a, b]));

        ours.merge(IndividualState::new(add(&mallory, key())));
        assert_eq!(ours.prekeys(), &HashSet::from([a, b]));
        assert!(ours
            .prekey_ops()
            .values()
            .all(|op| op.issuer() == Identifier::from(ours.id())));
    }

    /// Rotations that retire each other's keys leave no live prekey: nothing to
    /// pick, rather than a panic.
    #[test]
    fn an_individual_with_no_live_prekeys_has_none_to_pick() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let (a, b) = (key(), key());
        let mut individual = IndividualState::new(add(&signer, a));
        individual
            .receive_prekey_op(rotate(&signer, a, b))
            .expect("same issuer");
        individual
            .receive_prekey_op(rotate(&signer, b, a))
            .expect("same issuer");
        assert!(individual.prekeys().is_empty());
        assert_eq!(individual.pick_prekey(doc()), None);
    }
}
