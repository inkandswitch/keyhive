//! A single user agent.

pub mod state;

use super::{identifier::Identifier, verifiable::Verifiable};
use crate::crypto::{digest::Digest, share_key::ShareKey};
use base64::prelude::*;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use state::PrekeyState;
use std::collections::HashSet;

/// Single agents with no internal membership.
///
/// `Individual`s can be thought of as the terminal agents. They represent
/// keys that may sign ops, be delegated capabilties to [`Document`]s and [`Group`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Individual {
    /// The public key identifier.
    pub id: Identifier,

    /// [`ShaerKey`] pre-keys.
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
    pub prekeys: HashSet<ShareKey>,

    /// The state used to materialize `prekeys`.
    pub prekey_state: PrekeyState,
}

impl Individual {
    pub fn generate(signer: &ed25519_dalek::SigningKey) -> Self {
        let state = PrekeyState::generate(signer, 8);
        Self {
            id: signer.verifying_key().into(),
            prekeys: state.materialize(),
            prekey_state: state,
        }
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

// FIXME required?
impl std::fmt::Display for Individual {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.id.to_bytes()))
    }
}

impl From<VerifyingKey> for Individual {
    fn from(verifier: VerifyingKey) -> Self {
        Individual {
            id: verifier.into(),
            prekeys: HashSet::new(),
            prekey_state: PrekeyState::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndividualOp {
    pub verifier: VerifyingKey,
    pub op: ReadKeyOp,
    pub pred: HashSet<Digest<Individual>>,
}

// FIXME move to each Doc
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadKeyOp {
    Add(AddReadKey),
    Remove(VerifyingKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddReadKey {
    pub group: VerifyingKey,
    pub key: x25519_dalek::PublicKey,
}

impl PartialOrd for Individual {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.id.to_bytes().partial_cmp(&other.id.to_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    // FIXME proptest

    #[test]
    fn test_to_bytes() {
        let id = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();

        let individual: Individual = id.into();
        assert_eq!(individual.id.to_bytes(), id.to_bytes());
    }
}
