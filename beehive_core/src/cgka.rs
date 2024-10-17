pub mod beekem;
pub mod error;
pub mod treemath;

use beekem::{BeeKEM, PublicKey, SecretKey};
use error::CGKAError;
use serde::{Deserialize, Serialize};
use x25519_dalek;

use crate::{
    crypto::{encrypted::Encrypted, hash::Hash},
    principal::identifier::Identifier,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct CGKA {
    tree: BeeKEM,
    // /// Ops: Add, Remove, Rotate
    // ops: ...,
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
        Ok(Self {
            tree: BeeKEM::new(participants, owner_id, owner_pk, owner_sk)?,
        })
    }

    pub fn with_new_owner_id(&self, my_id: Identifier) -> Result<Self, CGKAError> {
        let mut cgka = self.clone();
        cgka.tree.set_owner_id(my_id)?;
        Ok(cgka)
    }
}

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn secret(&mut self, owner_sk: SecretKey) -> Result<SecretKey, CGKAError> {
        // Work from my leaf index up
        self.tree.decrypt_tree_secret(owner_sk)
    }

    /// Add participant.
    pub fn add(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        owner_sk: SecretKey,
    ) -> Result<(), CGKAError> {
        self.tree.push_leaf(id, pk)?;
        self.tree.encrypt_owner_path(owner_sk)
    }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier, owner_sk: SecretKey) -> Result<(), CGKAError> {
        self.tree.remove_id(id)?;
        self.tree.encrypt_owner_path(owner_sk)
    }

    /// Rotate key.
    // TODO: Should this only work for the owner path?
    pub fn update(
        &mut self,
        id: Identifier,
        new_pk: PublicKey,
        new_sk: SecretKey,
    ) -> Result<(), CGKAError> {
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
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit},
        ChaCha20Poly1305, Nonce, XChaCha20Poly1305,
    };
    use rand::RngCore;
    use std::str;

    use x25519_dalek::StaticSecret;

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
        println!("**********Encrypting with {:?}", secret.to_bytes());
        let cipher = XChaCha20Poly1305::new(&secret.to_bytes().into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let encrypted_secret_bytes = cipher
            .encrypt(&nonce.into(), msg.as_ref())
            .map_err(CGKAError::Encryption)?;
        Ok(Encrypted::new(nonce.into(), encrypted_secret_bytes.into()))
    }

    fn decrypt_msg(encrypted: Encrypted<String>, secret: SecretKey) -> Result<String, CGKAError> {
        println!("decrypt_msg");
        println!("**********Decrypting with {:?}", secret.to_bytes());
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
        println!("-- all_decrypt");
        let mut cgka = cgka.clone();
        let mut count = 0;
        for p in participants {
            println!("---! next decrypt, idx: {count}");
            count += 1;
            cgka = cgka.with_new_owner_id(p.id)?;
            println!("---! now for a secret");
            let secret = cgka.secret(p.sk.clone())?;
            println!("---! next decryptDONE --");
            assert_eq!(msg, decrypt_msg(encrypted.clone(), secret)?)
        }
        Ok(())
    }

    fn n_participants_encrypt_and_decrypt(n: u32) -> Result<(), CGKAError> {
        let mut msg = String::from("This is a message!");
        let participants = setup_participants(n);
        let mut cgka = setup_cgka(&participants, 0);
        let mut count = 0;
        for p in participants.clone() {
            println!("\n\n- n: {n}, idx: {count}");
            println!("My sk: {:?}", p.sk.to_bytes());
            count += 1;
            println!("-- with_new_owner");
            cgka = cgka.with_new_owner_id(p.id)?;
            println!("-- update");
            cgka.update(p.id, p.pk, p.sk.clone())?;
            println!("-- secret (my initial sk is {:?})", p.sk.to_bytes());
            let secret = cgka.secret(p.sk)?;
            msg += &n.to_string();
            println!("-- > encrypt_msg");
            let encrypted = encrypt_msg(&msg, secret)?;
            println!("- {n} -");
            all_decrypt_msg(&participants, &cgka, &msg, &encrypted)?;
        }
        Ok(())
    }

    #[test]
    fn test_simple_add() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let owner_sk = participants[0].sk.clone();
        let initial_participant_count = participants.len();
        let mut cgka = setup_cgka(&participants, 0);
        let new_p = setup_participant();
        cgka.add(new_p.id, new_p.pk, owner_sk.clone())?;
        assert_eq!(cgka.tree.id_count(), initial_participant_count as u32 + 1);
        Ok(())
    }

    #[test]
    fn test_simple_add_and_remove() -> Result<(), CGKAError> {
        let participants = setup_participants(2);
        let owner_sk = participants[0].sk.clone();
        let initial_participant_count = participants.len();
        let mut cgka = setup_cgka(&participants, 0);
        cgka.remove(participants[1].id, owner_sk.clone())?;
        assert_eq!(cgka.id_count(), initial_participant_count as u32 - 1);
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
    fn test_1_to_16_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        for n in 1..16 {
            println!("{n}");
            n_participants_encrypt_and_decrypt(n)?;
        }
        Ok(())
    }

    #[test]
    fn test_1_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(1)
    }

    #[test]
    fn test_2_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(2)
    }

    #[test]
    fn test_3_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(3)
    }

    #[test]
    fn test_4_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(4)
    }

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

    #[test]
    fn test_8_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(8)
    }

    // #[test]
    // fn test_9_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(9)
    // }

    #[test]
    fn test_16_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
        n_participants_encrypt_and_decrypt(16)
    }

    // #[test]
    // fn test_200_participants_encrypt_and_decrypt() -> Result<(), CGKAError> {
    //     n_participants_encrypt_and_decrypt(200)
    // }
}
