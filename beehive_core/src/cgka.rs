pub mod beekem;
pub mod error;
pub mod message;
pub mod treemath;

use beekem::{BeeKEM, PublicKey, SecretKey};
use bincode;
use error::CGKAError;
use message::CGKAMessage;
use serde::{Deserialize, Serialize};

use crate::{crypto::hash::Hash, principal::identifier::Identifier};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CGKA {
    owner_id: Identifier,
    owner_pk: PublicKey,
    tree: BeeKEM,
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
        if !participants.iter().any(|(id, pk)| *id == owner_id && *pk == owner_pk) {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        let mut tree = BeeKEM::new(participants)?;
        tree.encrypt_path(owner_id, owner_pk, owner_sk)?;
        Ok(Self {
            owner_id,
            owner_pk,
            tree,
        })
    }

    pub fn with_new_owner_id(&self, my_id: Identifier) -> Result<Self, CGKAError> {
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_pk = *cgka.tree.public_key_for_id(my_id)?;
        Ok(cgka)
    }
}

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn secret(&mut self, owner_sk: SecretKey) -> Result<SecretKey, CGKAError> {
        // Work from my leaf index up
        self.tree.decrypt_tree_secret(self.owner_id, owner_sk)
    }

    /// Add participant.
    pub fn add(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        owner_sk: SecretKey,
    ) -> Result<Option<CGKAMessage>, CGKAError> {
        let leaf_index = self.tree.push_leaf(id, pk)?;
        let owner_path = self.tree.encrypt_path(self.owner_id, self.owner_pk, owner_sk)?;
        // TODO: When should this be None? For example, if we've already applied this
        // add.
        Ok(Some(CGKAMessage::Add{ id, pk, leaf_index, owner_path }))
    }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier, owner_sk: SecretKey) -> Result<Option<CGKAMessage>, CGKAError> {
        if self.group_size() == 1 {
            return Err(CGKAError::RemoveLastMember);
        }
        let leaf_index = self.tree.remove_id(id)?;
        let owner_path = self.tree.encrypt_path(self.owner_id, self.owner_pk, owner_sk)?;
        // TODO: When should this be None? For example, if we've already applied this
        // remove.
        Ok(Some(CGKAMessage::Remove { id, leaf_index, owner_path }))
    }

    /// Update key pair for this Identifier.
    // TODO: Should this only work for the owner path?
    pub fn update(
        &mut self,
        id: Identifier,
        new_pk: PublicKey,
        new_sk: SecretKey,
    ) -> Result<Option<CGKAMessage>, CGKAError> {
        let new_path = self.tree.encrypt_path(id, new_pk, new_sk)?;
        if id == self.owner_id {
            self.owner_pk = new_pk;
        }
        Ok(Some(CGKAMessage::Update { id, new_path }))
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// Merge
    pub fn merge(&mut self, msg: CGKAMessage) -> Result<Option<CGKAMessage>, CGKAError> {
        match msg {
            CGKAMessage::Add { id, pk, leaf_index, owner_path } => {
                todo!()
            },
            CGKAMessage::Merge => {
                todo!()
            },
            CGKAMessage::Remove { id, leaf_index, owner_path } => {
                todo!()
            },
            CGKAMessage::Update { id, new_path } => {
                // FIXME
                Ok(None)
            }
        }
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
            cgka = cgka.with_new_owner_id(p.id)?;
            let secret = cgka.secret(p.sk.clone())?;
            assert_eq!(msg, decrypt_msg(encrypted.clone(), secret)?)
        }
        Ok(())
    }

    fn update_every_path(cgka: &CGKA, participants: &Vec<Participant>) -> Result<(), CGKAError> {
        let mut cgka = cgka.clone();
        for p in participants {
            cgka = cgka.with_new_owner_id(p.id)?;
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
            cgka = cgka.with_new_owner_id(p.id)?;
            println!("\n-- update");
            let (new_pk, new_sk) = key_pair();
            p.pk = new_pk;
            p.sk = new_sk.clone();
            cgka.update(p.id, new_pk, new_sk.clone())?;
            println!("\n-- get secret");
            let secret = cgka.secret(new_sk.clone())?;
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
        cgka.remove(participants[1].id, owner_sk.clone())?;
        assert_eq!(cgka.group_size(), initial_participant_count as u32 - 1);
        Ok(())
    }

    #[test]
    fn test_single_identifier_encrypt_and_decrypt() -> Result<(), CGKAError> {
        let participants = setup_participants(1);
        let mut cgka = setup_cgka(&participants, 0);
        let me = participants[0].clone();
        cgka.update(me.id, me.pk, me.sk.clone())?;
        let secret = cgka.secret(me.sk.clone())?;
        let msg = "This is a message.";
        let encrypted = encrypt_msg(msg, secret)?;
        let secret2 = cgka.secret(me.sk)?;
        assert_eq!(msg, &decrypt_msg(encrypted, secret2)?);
        Ok(())
    }

    #[test]
    fn test_simple_encrypt_and_decrypt() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let mut cgka = setup_cgka(&participants, 0);
        let (me_pk, me_sk) = key_pair();
        cgka.update(participants[0].id, me_pk, me_sk.clone())?;
        let (p1_pk, p1_sk) = key_pair();
        cgka.update(participants[1].id, p1_pk, p1_sk.clone())?;
        let secret = cgka.secret(me_sk)?;
        let msg = "This is a message.";
        let encrypted = encrypt_msg(msg, secret)?;
        let mut cgka2 = cgka.with_new_owner_id(participants[1].id)?;
        let secret2 = cgka2.secret(p1_sk)?;
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
                cgka.remove(p.id, owner_sk.clone())?;
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
        cgka.with_new_owner_id(new_p.id)?
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
            cgka.remove(p.id, owner_sk.clone())?;
        }
        each_encrypts_and_all_decrypt(&cgka, &participants)
    }

    #[test]
    fn test_remove_from_left() -> Result<(), CGKAError> {
        let participants = setup_participants(8);
        let mut cgka = setup_cgka(&participants, 0);
        update_every_path(&cgka, &participants)?;
        let new_owner = participants[4].clone();
        cgka = cgka.with_new_owner_id(new_owner.id)?;
        let mut new_participants = Vec::new();
        for (idx, p) in participants.iter().enumerate() {
            if idx < 4 {
                cgka.remove(p.id, new_owner.sk.clone())?;
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


    // #[test]
    // fn test_fork_update_and_merge() -> Result<(), CGKAError> {
    //     let participants = setup_participants(8);
    //     let p1 = participants[1].clone();
    //     let p5 = participants[5].clone();
    //     let initial_cgka = setup_cgka(&participants, 0);
    //     update_every_path(&initial_cgka, &participants)?;
    //     let mut p1_cgka = initial_cgka.with_new_owner_id(p1.id)?;
    //     let mut p5_cgka = initial_cgka.with_new_owner_id(p5.id)?;
    //     assert_eq!(p1_cgka.tree.hash(), p5_cgka.tree.hash());

    //     let (p1_pk, p1_sk) = key_pair();
    //     let p1_msg = p1_cgka.update(p1.id, p1_pk, p1_sk)?.expect("Should have message");
    //     let (p5_pk, p5_sk) = key_pair();
    //     let p5_msg = p5_cgka.update(p5.id, p5_pk, p5_sk)?.expect("Should have message");

    //     p1_cgka.merge(p5_msg)?;
    //     p5_cgka.merge(p1_msg)?;

    //     // TODO: Better to try to encrypt and decrypt using these.
    //     assert_eq!(p1_cgka.tree.hash(), p5_cgka.tree.hash());
    //     Ok(())
    // }

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
