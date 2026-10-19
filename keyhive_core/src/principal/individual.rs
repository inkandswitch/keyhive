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
        let id = IndividualId(initial_op.issuer());
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

    /// The prekey to seat this individual with in `doc_id`'s tree, or `None`
    /// if it has no live prekeys (rotations can retire every one).
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
    use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner};
    use std::collections::BTreeSet;

    fn add(signer: &MemorySigner, share_key: ShareKey) -> KeyOp {
        KeyOp::Add(Arc::new(
            signer.try_sign_sync(AddKeyOp { share_key }).expect("signs"),
        ))
    }

    fn rotate(signer: &MemorySigner, old: ShareKey, new: ShareKey) -> KeyOp {
        KeyOp::Rotate(Arc::new(
            signer
                .try_sign_sync(RotateKeyOp { old, new })
                .expect("signs"),
        ))
    }

    fn key() -> ShareKey {
        ShareSecretKey::generate(&mut rand::thread_rng()).share_key()
    }

    /// An individual with `n` live prekeys, its ops inserted in shuffled order.
    fn with_prekeys(signer: &MemorySigner, n: usize) -> Individual {
        use rand::seq::SliceRandom;
        let mut ops: Vec<KeyOp> = (0..n).map(|_| add(signer, key())).collect();
        ops.shuffle(&mut rand::thread_rng());
        let mut ops = ops.into_iter();
        let mut individual = Individual::new(ops.next().expect("at least one"));
        for op in ops {
            individual.receive_prekey_op(op).expect("same issuer");
        }
        individual
    }

    fn doc() -> DocumentId {
        DocumentId::generate(&mut rand::thread_rng())
    }

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
            let mut individual = Individual::new(ops.next().expect("nonempty"));
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

    /// Rotations that retire each other's keys leave no live prekey: nothing to
    /// pick, rather than a panic.
    #[test]
    fn an_individual_with_no_live_prekeys_has_none_to_pick() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let (a, b) = (key(), key());
        let mut individual = Individual::new(add(&signer, a));
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
