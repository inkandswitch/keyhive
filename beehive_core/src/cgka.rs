pub mod beekem;
pub mod error;
pub mod treemath;

use std::collections::BTreeMap;

use beekem::BeeKEM;
use error::CGKAError;
use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek;

use crate::{crypto::{encrypted::Encrypted, hash::Hash}, principal::identifier::Identifier};
type PublicKey = x25519_dalek::PublicKey;
type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub struct CGKA {
    tree: BeeKEM,
    // /// Ops: Add, Remove, Rotate
    // ops: ...,
}

/// Constructors
impl CGKA {
    /// We assume participants are in causal order.
    pub fn new(participants: Vec<(Identifier, PublicKey)>, my_id: Identifier) -> Result<Self, CGKAError> {
        Ok(Self {
            tree: BeeKEM::new(participants, my_id)?,
        })
    }
}

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn get_secret(&self, sk: SecretKey) -> SecretKey {
        // Work from my leaf index up
        todo!()
    }

    /// Add participant.
    pub fn add(&mut self, id: Identifier, pk: PublicKey) -> Result<(), CGKAError> {
        self.tree.push_leaf(id, pk)
    }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier) -> Result<(), CGKAError> {
        self.tree.remove_id(id)
    }

    /// Rotate key.
    pub fn update(&mut self, id: Identifier, new_pk: PublicKey, new_sk: SecretKey) -> Result<(), CGKAError> {
        self.tree.encrypt_path(id, new_pk, new_sk)
    }

    /// Identifier count
    pub fn id_count(&self) -> u32 {
        self.tree.id_count()
    }

    /// Merge
    // pub fn merge(&mut self, ops: ...) {
    //     todo!()
    // }

    /// Hash of the tree
    pub fn hash(&self) -> Hash<CGKA> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::StaticSecret;

    use super::*;

    fn setup_participant() -> (Identifier, PublicKey) {
        let id = Identifier::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key());
        let secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let pk = PublicKey::from(&secret);
        (id, pk)
    }

    #[test]
    fn test_simple_add() -> Result<(), CGKAError> {
        let me = setup_participant();
        let mut participants = vec![me];
        participants.push(setup_participant());
        let participant_count = participants.len();
        let cgka = CGKA::new(participants, me.0)?;
        assert_eq!(cgka.tree.id_count(), participant_count as u32);
        Ok(())
    }

    #[test]
    fn test_simple_add_and_remove() -> Result<(), CGKAError> {
        let me = setup_participant();
        let p1 = setup_participant();
        let participants = vec![me, p1];
        let initial_participant_count = participants.len();
        let mut cgka = CGKA::new(participants, me.0)?;
        cgka.remove(p1.0)?;
        assert_eq!(cgka.id_count(), initial_participant_count as u32 - 1);
        Ok(())
    }
}

//////////////////////////////////
//////////////////////////////////

// Derive key pair
fn dkp(x: &[u8]) -> (PublicKey, SecretKey) {
    todo!()
}

// Key derivation function
// Second input is used to prevent collisions (e.g. "path" or "node")
// fn kdf(&[u8], &[u8]) -> ???
