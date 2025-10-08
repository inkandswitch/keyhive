//! A single user agent.

pub mod id;
pub mod op;
pub mod state;

use self::op::KeyOp;
use super::{agent::id::AgentId, document::id::DocumentId};
use crate::{
    contact_card::ContactCard,
    crypto::{share_key::ShareKey, signed::VerificationError, verifiable::Verifiable},
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_more::Debug;
use ed25519_dalek::VerifyingKey;
use id::IndividualId;
use serde::{Deserialize, Serialize};
use state::PrekeyState;
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;
use tracing::instrument;

#[cfg(any(feature = "test_utils", test))]
use crate::crypto::{signed::SigningError, signer::async_signer::AsyncSigner};

#[cfg(any(feature = "test_utils", test))]
use std::num::NonZeroUsize;

/// Single agents with no internal membership.
///
/// `Individual`s can be thought of as the terminal agents. They represent
/// keys that may sign ops, be delegated capabilties to
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
    pub async fn generate<R: rand::CryptoRng + rand::RngCore, S: AsyncSigner>(
        signer: &S,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let prekey_state =
            PrekeyState::generate(signer, NonZeroUsize::new(8).unwrap(), csprng).await?;

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
    pub fn pick_prekey(&self, doc_id: DocumentId) -> &ShareKey {
        let mut bytes: Vec<u8> = self.id.to_bytes().to_vec();
        bytes.extend_from_slice(&doc_id.to_bytes());

        let prekeys_len = self.prekeys.len();
        let idx = pseudorandom_in_range(bytes.as_slice(), prekeys_len);

        self.prekeys.iter().nth(idx).expect("index to be in range")
    }

    pub fn prekey_ops(&self) -> &CaMap<KeyOp> {
        self.prekey_state.ops()
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
    use crate::{
        crypto::signer::sync_signer::SyncSigner, principal::individual::op::add_key::AddKeyOp,
    };

    #[test]
    fn test_to_bytes() {
        test_utils::init_logging();
        let mut csprng = rand::thread_rng();
        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
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
}
