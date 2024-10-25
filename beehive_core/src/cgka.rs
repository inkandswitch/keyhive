pub mod beekem;
pub mod error;
pub mod secret_store;
pub mod treemath;

use beekem::{BeeKEM, PublicKey, SecretKey, TreeChange, TreePath};
use bincode;
use error::CGKAError;
use secret_store::SecretKeyMap;
use serde::{Deserialize, Serialize};

use crate::principal::identifier::Identifier;

#[derive(Clone, Deserialize, Serialize)]
pub struct CGKA {
    owner_id: Identifier,
    owner_pk: PublicKey,
    // TODO: How do we safely store these in memory?
    // Would it be better for this to be a new type to hide the fact we
    // need to convert the PublicKey to bytes for the key?
    owner_sks: SecretKeyMap,
    tree: BeeKEM,
    changes: Vec<TreeChange>,
}

/// Constructors
impl CGKA {
    /// We assume participants are in causal order.
    pub fn new(
        participants: Vec<(Identifier, PublicKey)>,
        owner_id: Identifier,
        owner_pk: PublicKey,
        owner_sk: SecretKey,
    ) -> Result<Self, CGKAError> {
        if !participants
            .iter()
            .any(|(id, pk)| *id == owner_id && *pk == owner_pk)
        {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        let tree = BeeKEM::new(participants)?;
        let mut owner_sks = SecretKeyMap::new();
        owner_sks.insert(owner_pk, owner_sk);
        let mut cgka = Self {
            owner_id,
            owner_pk,
            owner_sks,
            tree,
            changes: Vec::new(),
        };
        cgka.tree
            .encrypt_path(owner_id, owner_pk, &mut cgka.owner_sks)?;
        Ok(cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: Identifier,
        pk: PublicKey,
        sk: SecretKey,
    ) -> Result<Self, CGKAError> {
        // TODO: Is the first public key the right thing to check? What about with conflicts?
        if !(pk == self.tree.multikey_for_id(my_id)?.first_public_key()) {
            return Err(CGKAError::PublicKeyNotFound);
        }
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_pk = pk;
        cgka.owner_sks = SecretKeyMap::new();
        cgka.owner_sks.insert(pk, sk);
        Ok(cgka)
    }
}

// TODO: Do we need this?
// impl Debug for LeafNode {
//   fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//     f.debug_struct("CGKA")
//       .field("owner_id", &self.owner_id)
//       .finish()
//   }
// }

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn secret(&mut self) -> Result<SecretKey, CGKAError> {
        println!("secret()");
        // Work from my leaf index up
        self.tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
    }

    /// Add participant.
    pub fn add(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        owner_sk: SecretKey,
    ) -> Result<Option<TreeChange>, CGKAError> {
        let leaf_index = self.tree.push_leaf(id, pk)?;
        let tree_change =
            self.tree
                .encrypt_path(self.owner_id, self.owner_pk, &mut self.owner_sks)?;
        // let op = CGKAOperation::Add{ id, pk, leaf_index, owner_path };
        // let change = TreeChange { changer_id: self.owner_id, op, undo };
        self.changes.push(tree_change.clone());
        // TODO: When should this be None? For example, if we've already applied this
        // add.
        Ok(Some(tree_change))
    }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier) -> Result<Option<TreeChange>, CGKAError> {
        println!("| Removing id {:?}", id.verifying_key);
        if self.group_size() == 1 {
            return Err(CGKAError::RemoveLastMember);
        }
        let leaf_index = self.tree.remove_id(id)?;
        let tree_change =
            self.tree
                .encrypt_path(self.owner_id, self.owner_pk, &mut self.owner_sks)?;
        // let op = CGKAOperation::Remove { id, leaf_index, owner_path };
        // let change = TreeChange { changer_id: self.owner_id, op, undo };
        self.changes.push(tree_change.clone());
        // TODO: When should this be None? For example, if we've already applied this
        // remove.
        Ok(Some(tree_change))
    }

    /// Update key pair for this Identifier.
    // TODO: Should this only work for the owner path?
    pub fn update(
        &mut self,
        id: Identifier,
        new_pk: PublicKey,
        new_sk: SecretKey,
    ) -> Result<Option<TreeChange>, CGKAError> {
        self.owner_sks.insert(new_pk, new_sk);
        let tree_change = self.tree.encrypt_path(id, new_pk, &mut self.owner_sks)?;
        if id == self.owner_id {
            self.owner_pk = new_pk;
        }
        // let op = CGKAOperation::Update { id, new_path };
        // let change = TreeChange { changer_id: self.owner_id, op, undo };
        self.changes.push(tree_change.clone());
        // TODO: When should this be None? For example, if we've already applied this
        // update.
        Ok(Some(tree_change))
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// Merge
    pub fn merge(&mut self, change: TreeChange) -> Result<(), CGKAError> {
        self.tree.apply_path(change)
    }

    // /// Hash of the tree
    // pub fn hash(&self) -> Hash<CGKA> {
    //     Hash::hash(self.clone())
    // }
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305,
    };
    use ed25519_dalek::VerifyingKey;
    use rand::RngCore;
    use std::str;

    use x25519_dalek::StaticSecret;

    use crate::crypto::encrypted::Encrypted;

    use super::*;

    #[derive(Clone)]
    struct Participant {
        id: Identifier,
        pk: PublicKey,
        sk: SecretKey,
    }

    fn setup_participant() -> Participant {
        let id = Identifier::new(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key(),
        );
        let (pk, sk) = key_pair();
        Participant { id, pk, sk }
    }

    fn setup_participants(n: u32) -> Vec<Participant> {
        assert!(n > 0);
        let mut ps = Vec::new();
        for _ in 0..n {
            ps.push(setup_participant());
        }
        ps
    }

    fn setup_cgka(participants: &Vec<Participant>, p_idx: usize) -> CGKA {
        let owner = participants[p_idx].clone();
        CGKA::new(
            participants.into_iter().map(|p| (p.id, p.pk)).collect(),
            owner.id,
            owner.pk,
            owner.sk.clone(),
        )
        .expect("CGKA construction failed")
    }

    fn key_pair() -> (PublicKey, SecretKey) {
        let sk = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        (pk, sk)
    }

    fn encrypt_msg(msg: &str, secret: SecretKey) -> Result<Encrypted<String>, CGKAError> {
        let cipher = XChaCha20Poly1305::new(&secret.to_bytes().into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let encrypted_secret_bytes = cipher
            .encrypt(&nonce.into(), msg.as_ref())
            .map_err(CGKAError::Encryption)?;
        Ok(Encrypted::new(nonce.into(), encrypted_secret_bytes.into()))
    }

    fn decrypt_msg(encrypted: Encrypted<String>, secret: SecretKey) -> Result<String, CGKAError> {
        let cipher = XChaCha20Poly1305::new(&secret.to_bytes().into());
        let decrypted_bytes = cipher
            .decrypt(&encrypted.nonce.into(), encrypted.ciphertext.as_ref())
            .map_err(|e| CGKAError::Decryption(e.to_string()))?;
        Ok(str::from_utf8(&decrypted_bytes)
            .map_err(|e| CGKAError::Decryption(e.to_string()))?
            .to_string())
    }

    fn all_decrypt_msg(
        participants: &Vec<Participant>,
        cgka: &CGKA,
        msg: &str,
        encrypted: &Encrypted<String>,
    ) -> Result<(), CGKAError> {
        let mut cgka = cgka.clone();
        let mut count = 0;
        for p in participants {
            count += 1;
            cgka = cgka.with_new_owner(p.id, p.pk, p.sk.clone())?;
            let secret = cgka.secret()?;
            assert_eq!(msg, decrypt_msg(encrypted.clone(), secret)?)
        }
        Ok(())
    }

    fn update_every_path(cgka: &CGKA, participants: &Vec<Participant>) -> Result<(), CGKAError> {
        let mut cgka = cgka.clone();
        for p in participants {
            cgka = cgka.with_new_owner(p.id, p.pk, p.sk.clone())?;
            cgka.update(p.id, p.pk, p.sk.clone())?;
        }
        Ok(())
    }

    fn each_encrypts_and_all_decrypt(
        cgka: &CGKA,
        participants: &Vec<Participant>,
    ) -> Result<(), CGKAError> {
        let mut msg = String::from("This is a message!");
        let mut count = 0;
        let mut cgka = cgka.clone();
        let n = participants.len();
        let mut participants = participants.clone();
        for idx in 0..participants.len() {
            let p = &mut participants[idx];
            println!("========================================\n\n");
            println!("========================================");
            println!("- n: {n}, idx: {count}");
            println!("========================================");
            println!("My sk: {:?}", p.sk.to_bytes());
            count += 1;
            println!("\n-- with_new_owner");
            cgka = cgka.with_new_owner(p.id, p.pk, p.sk.clone())?;
            println!("\n-- update");
            let (new_pk, new_sk) = key_pair();
            p.pk = new_pk;
            p.sk = new_sk.clone();
            cgka.update(p.id, new_pk, new_sk.clone())?;
            println!("\n-- get secret");
            let secret = cgka.secret()?;
            msg += &n.to_string();
            println!("\n-- > encrypt_msg");
            let encrypted = encrypt_msg(&msg, secret)?;
            println!("\n- {n} now all_decrypt_msg -");
            all_decrypt_msg(&participants, &cgka, &msg, &encrypted)?;
        }
        Ok(())
    }

    fn n_participants_encrypt_and_decrypt(n: u32) -> Result<(), CGKAError> {
        let participants = setup_participants(n);
        let cgka = setup_cgka(&participants, 0);
        each_encrypts_and_all_decrypt(&cgka, &participants)
    }

    #[test]
    fn test_simple_add() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let owner_sk = participants[0].sk.clone();
        let initial_participant_count = participants.len();
        let mut cgka = setup_cgka(&participants, 0);
        let new_p = setup_participant();
        cgka.add(new_p.id, new_p.pk, owner_sk.clone())?;
        assert_eq!(
            cgka.tree.member_count(),
            initial_participant_count as u32 + 1
        );
        Ok(())
    }

    #[test]
    fn test_simple_add_and_remove() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let owner_sk = participants[0].sk.clone();
        let initial_participant_count = participants.len();
        let mut cgka = setup_cgka(&participants, 0);
        cgka.remove(participants[1].id)?;
        assert_eq!(cgka.group_size(), initial_participant_count as u32 - 1);
        Ok(())
    }

    #[test]
    fn test_single_identifier_encrypt_and_decrypt() -> Result<(), CGKAError> {
        let participants = setup_participants(1);
        let mut cgka = setup_cgka(&participants, 0);
        let me = participants[0].clone();
        cgka.update(me.id, me.pk, me.sk.clone())?;
        let secret = cgka.secret()?;
        let msg = "This is a message.";
        let encrypted = encrypt_msg(msg, secret)?;
        let secret2 = cgka.secret()?;
        assert_eq!(msg, &decrypt_msg(encrypted, secret2)?);
        Ok(())
    }

    #[test]
    fn test_simple_encrypt_and_decrypt() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let mut cgka = setup_cgka(&participants, 0);
        let (new_me_pk, new_me_sk) = key_pair();
        cgka.update(participants[0].id, new_me_pk, new_me_sk.clone())?;
        let (new_p1_pk, new_p1_sk) = key_pair();
        cgka.update(participants[1].id, new_p1_pk, new_p1_sk.clone())?;
        let secret = cgka.secret()?;
        let msg = "This is a message.";
        let encrypted = encrypt_msg(msg, secret)?;
        let p1 = participants[1].clone();
        let mut cgka2 = cgka.with_new_owner(p1.id, new_p1_pk, new_p1_sk.clone())?;
        let secret2 = cgka2.secret()?;
        assert_eq!(msg, &decrypt_msg(encrypted, secret2)?);
        Ok(())
    }

    #[test]
    fn test_remove_every_other_leaf() -> Result<(), CGKAError> {
        let participants = setup_participants(8);
        let mut cgka = setup_cgka(&participants, 0);
        update_every_path(&cgka, &participants)?;
        let owner_sk = participants[0].sk.clone();
        let mut new_participants = Vec::new();
        for (idx, p) in participants.iter().enumerate() {
            if idx % 2 == 0 {
                new_participants.push(p.clone());
            } else {
                cgka.remove(p.id)?;
            }
        }
        each_encrypts_and_all_decrypt(&cgka, &new_participants)
    }

    #[test]
    fn test_grow_tree() -> Result<(), CGKAError> {
        let mut participants = setup_participants(8);
        let mut cgka = setup_cgka(&participants, 0);
        update_every_path(&cgka, &participants)?;
        let new_p = setup_participant();
        participants.push(new_p.clone());
        cgka.add(new_p.id, new_p.pk, participants[0].sk.clone())?;
        cgka.with_new_owner(new_p.id, new_p.pk, new_p.sk.clone())?
            .update(new_p.id, new_p.pk, new_p.sk.clone())?;
        each_encrypts_and_all_decrypt(&cgka, &participants)
    }

    #[test]
    fn test_remove_from_right() -> Result<(), CGKAError> {
        let mut participants = setup_participants(8);
        let mut cgka = setup_cgka(&participants, 0);
        update_every_path(&cgka, &participants)?;
        let owner_sk = participants[0].sk.clone();
        for _ in 0..4 {
            let p = participants.pop().unwrap();
            cgka.remove(p.id)?;
        }
        each_encrypts_and_all_decrypt(&cgka, &participants)
    }

    #[test]
    fn test_remove_from_left() -> Result<(), CGKAError> {
        let participants = setup_participants(8);
        let mut cgka = setup_cgka(&participants, 0);
        update_every_path(&cgka, &participants)?;
        let new_owner = participants[4].clone();
        cgka = cgka.with_new_owner(new_owner.id, new_owner.pk, new_owner.sk.clone())?;
        let mut new_participants = Vec::new();
        for (idx, p) in participants.iter().enumerate() {
            if idx < 4 {
                cgka.remove(p.id)?;
            } else {
                new_participants.push(p.clone());
            }
        }
        each_encrypts_and_all_decrypt(&cgka, &new_participants)
    }

    #[test]
    fn test_1_to_16_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        for n in 1..17 {
            n_participants_encrypt_and_decrypt(n)?;
        }
        Ok(())
    }

    fn fork_update_and_merge(
        participant_count: u32,
        p_idx_a: usize,
        p_idx_b: usize,
        removes: Vec<usize>,
    ) -> Result<(), CGKAError> {
        println!("------------------------------------------------------");
        println!("fork_update_and_merge: updates,    no removes");
        _fork_update_and_merge(participant_count, p_idx_a, p_idx_b, true, Vec::new())?;
        println!("------------------------------------------------------");
        println!("fork_update_and_merge: no updates, no removes");
        _fork_update_and_merge(participant_count, p_idx_a, p_idx_b, false, Vec::new())?;
        if !removes.is_empty() {
            println!("------------------------------------------------------");
            println!("fork_update_and_merge: updates,    removes");
            _fork_update_and_merge(participant_count, p_idx_a, p_idx_b, true, removes.clone())?;
            println!("------------------------------------------------------");
            println!("fork_update_and_merge: no updates, removes");
            _fork_update_and_merge(participant_count, p_idx_a, p_idx_b, false, removes)?;
        }
        Ok(())
    }

    fn _fork_update_and_merge(
        participant_count: u32,
        p_idx_a: usize,
        p_idx_b: usize,
        should_update_every_path: bool,
        removes: Vec<usize>,
    ) -> Result<(), CGKAError> {
        assert_ne!(p_idx_a, p_idx_b);
        let participants = setup_participants(participant_count);
        // TODO: Remove
        if !removes.is_empty() {
            println!("|||===== Removes: {:?}", removes.iter().map(|idx| (idx, participants[*idx].id.verifying_key)).collect::<Vec<(&usize, VerifyingKey)>>());
        }
        let p_a = participants[p_idx_a].clone();
        let p_b = participants[p_idx_b].clone();
        let mut initial_cgka = setup_cgka(&participants, 0);
        println!("\n\n update every path\n");
        if should_update_every_path {
            update_every_path(&initial_cgka, &participants)?;
        }
        if !removes.is_empty() {
            for idx in removes {
                assert!(idx != 0, "Can't remove owner!");
                initial_cgka.remove(participants[idx].id)?;
            }
        }
        let mut p_a_cgka = initial_cgka.with_new_owner(p_a.id, p_a.pk, p_a.sk.clone())?;
        let mut p_b_cgka = initial_cgka.with_new_owner(p_b.id, p_b.pk, p_b.sk.clone())?;
        println!("\n\n secret assert_eq\n");
        assert_eq!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        println!("\n\n\n pa update |a: LeafNodeIndex({p_idx_a})\n");
        let (p_a_pk, p_a_sk) = key_pair();
        let p_a_change = p_a_cgka
            .update(p_a.id, p_a_pk, p_a_sk)?
            .expect("Should have message");
        println!("\n\n secret assert_ne\n");
        assert_ne!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        println!("\n\n\n pb merge |b: LeafNodeIndex({p_idx_b})\n");
        p_b_cgka.merge(p_a_change)?;
        println!("\n secret for a\n");
        p_a_cgka.secret()?;
        println!("\n secret for b\n");
        p_b_cgka.secret()?;
        println!("\n\n secret assert_eq\n");
        assert_eq!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        println!("\n\n\n pb update |b: LeafNodeIndex({p_idx_b})\n");
        let (p_b_pk, p_b_sk) = key_pair();
        let p_b_change = p_b_cgka
            .update(p_b.id, p_b_pk, p_b_sk)?
            .expect("Should have message");
        println!("\n\n\n secret assert_ne\n");
        assert_ne!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        println!("\n\n\n pa merge |a: LeafNodeIndex({p_idx_a})\n");
        p_a_cgka.merge(p_b_change)?;
        println!("\n\n\n pb secret |b: LeafNodeIndex({p_idx_b})\n");
        p_b_cgka.secret()?;
        println!("\n\n\n pa secret |a: LeafNodeIndex({p_idx_a})\n");
        p_a_cgka.secret()?;
        println!("DONE!");
        println!("\n\n secret assert_eq\n");
        assert_eq!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        Ok(())
    }

    #[test]
    fn test_fork_update_and_merge_3_0_1() -> Result<(), CGKAError> {
        let participant_count = 3;
        let p_idx_a = 0;
        let p_idx_b = 1;
        let removes = Vec::new();
        fork_update_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_update_and_merge_3_1_2() -> Result<(), CGKAError> {
        let participant_count = 3;
        let p_idx_a = 1;
        let p_idx_b = 2;
        let removes = Vec::new();
        fork_update_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_update_and_merge_7_5_6() -> Result<(), CGKAError> {
        let participant_count = 7;
        let p_idx_a = 5;
        let p_idx_b = 6;
        let removes = vec![1, 2, 4];
        fork_update_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_update_and_merge_7_1_6() -> Result<(), CGKAError> {
        let participant_count = 7;
        let p_idx_a = 1;
        let p_idx_b = 6;
        let removes = vec![2, 4];
        fork_update_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    fn fork_concurrent_updates_and_merge(
        participant_count: u32,
        p_idx_a: usize,
        p_idx_b: usize,
        removes: Vec<usize>,
    ) -> Result<(), CGKAError> {
        _fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, true, Vec::new())?;
        _fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, false, Vec::new())?;
        if !removes.is_empty() {
            _fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, true, removes.clone())?;
            _fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, false, removes)?;
        }
        Ok(())
    }

    fn _fork_concurrent_updates_and_merge(
        participant_count: u32,
        p_idx_a: usize,
        p_idx_b: usize,
        should_update_every_path: bool,
        removes: Vec<usize>,
    ) -> Result<(), CGKAError> {
        let participants = setup_participants(participant_count);
        let p_a = participants[p_idx_a].clone();
        let p_b = participants[p_idx_b].clone();
        let mut initial_cgka = setup_cgka(&participants, 0);
        if should_update_every_path {
            update_every_path(&initial_cgka, &participants)?;
        }
        if !removes.is_empty() {
            for idx in removes {
                assert!(idx != 0, "Can't remove owner!");
                initial_cgka.remove(participants[idx].id)?;
            }
        }
        let mut p_a_cgka = initial_cgka.with_new_owner(p_a.id, p_a.pk, p_a.sk.clone())?;
        let mut p_b_cgka = initial_cgka.with_new_owner(p_b.id, p_b.pk, p_b.sk.clone())?;
        assert_eq!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        let (p_a_pk, p_a_sk) = key_pair();
        let p_a_change = p_a_cgka
            .update(p_a.id, p_a_pk, p_a_sk)?
            .expect("Should have message");
        let (p_b_pk2, p_b_sk2) = key_pair();
        let p_b_change = p_b_cgka
            .update(p_b.id, p_b_pk2, p_b_sk2)?
            .expect("Should have message");
        assert_ne!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        p_b_cgka.merge(p_a_change)?;
        assert!(!p_b_cgka.tree.has_root_key()?);
        let (p_b_pk3, p_b_sk3) = key_pair();
        let p_b_change2 = p_b_cgka
            .update(p_b.id, p_b_pk3, p_b_sk3)?
            .expect("Should have message");
        assert!(p_b_cgka.tree.has_root_key()?);
        assert_ne!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());
        // Changes will always be merged in causal order
        p_a_cgka.merge(p_b_change)?;
        p_a_cgka.merge(p_b_change2)?;
        assert_eq!(p_a_cgka.secret()?.to_bytes(), p_b_cgka.secret()?.to_bytes());

        Ok(())
    }

    #[test]
    fn test_fork_concurrent_updates_and_merge_3_0_1() -> Result<(), CGKAError> {
        let participant_count = 3;
        let p_idx_a = 0;
        let p_idx_b = 1;
        let removes = Vec::new();
        fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_concurrent_updates_and_merge_3_1_2() -> Result<(), CGKAError> {
        let participant_count = 3;
        let p_idx_a = 1;
        let p_idx_b = 2;
        let removes = Vec::new();
        fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_concurrent_updates_and_merge_7_5_6() -> Result<(), CGKAError> {
        let participant_count = 7;
        let p_idx_a = 5;
        let p_idx_b = 6;
        let removes = vec![1, 2, 4];
        fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    #[test]
    fn test_fork_concurrent_updates_and_merge_7_1_6() -> Result<(), CGKAError> {
        let participant_count = 7;
        let p_idx_a = 1;
        let p_idx_b = 6;
        let removes = vec![2, 4];
        fork_concurrent_updates_and_merge(participant_count, p_idx_a, p_idx_b, removes)
    }

    // #[test]
    // fn test_17_to_32_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     for n in 17..33 {
    //         println!("{n}");
    //         n_participants_encrypt_and_decrypt(n)?;
    //     }
    //     Ok(())
    // }

    // #[test]
    // fn test_1_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(1)
    // }

    // #[test]
    // fn test_2_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(2)
    // }

    // #[test]
    // fn test_3_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(3)
    // }

    // #[test]
    // fn test_4_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(4)
    // }

    // #[test]
    // fn test_5_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(5)
    // }

    // #[test]
    // fn test_6_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(6)
    // }

    // #[test]
    // fn test_7_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(7)
    // }

    // #[test]
    // fn test_8_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(8)
    // }

    // #[test]
    // fn test_9_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(9)
    // }

    // #[test]
    // fn test_16_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(16)
    // }

    // #[test]
    // fn test_200_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(200)
    // }
}
