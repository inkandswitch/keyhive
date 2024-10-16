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
        my_id: Identifier,
    ) -> Result<Self, CGKAError> {
        Ok(Self {
            tree: BeeKEM::new(participants, my_id)?,
        })
    }

    pub fn with_new_owner_id(&self, my_id: Identifier) -> Self {
        let mut cgka = self.clone();
        cgka.tree.with_new_owner_id(my_id);
        cgka
    }
}

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn secret(&self, sk: SecretKey) -> SecretKey {
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

    fn setup_participant() -> (Identifier, PublicKey) {
        let id = Identifier::new(
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key(),
        );
        let secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let pk = PublicKey::from(&secret);
        (id, pk)
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
            .encrypt(&nonce.into(), secret.as_ref())
            .map_err(CGKAError::Encryption)?;
        Ok(Encrypted::new(nonce.into(), msg.into()))
    }

    fn decrypt_msg(encrypted: Encrypted<String>, secret: SecretKey) -> Result<String, CGKAError> {
        let cipher = XChaCha20Poly1305::new(&secret.to_bytes().into());
        let decrypted_bytes = cipher
            .decrypt(&encrypted.nonce.into(), encrypted.ciphertext.as_ref())
            .map_err(CGKAError::Encryption)?;
        Ok(str::from_utf8(&decrypted_bytes)
            .map_err(|e| CGKAError::Decryption(e.to_string()))?
            .to_string())
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

    #[test]
    fn test_simple_encrypt_and_decrypt() -> Result<(), CGKAError> {
        let me = setup_participant();
        let p1 = setup_participant();
        let participants = vec![me, p1];
        let mut cgka = CGKA::new(participants, me.0)?;
        println!("0");
        let (me_pk, me_sk) = key_pair();
        cgka.update(me.0, me_pk, me_sk.clone())?;
        println!("0b");
        let (p1_pk, p1_sk) = key_pair();
        cgka.update(p1.0, p1_pk, p1_sk.clone())?;
        println!("1");
        let secret = cgka.secret(me_sk);
        println!("2");
        let msg = "This is a message.";
        let encrypted = encrypt_msg(msg, secret)?;
        println!("3");
        let cgka2 = cgka.with_new_owner_id(p1.0);
        let secret2 = cgka2.secret(p1_sk);
        assert_eq!(msg, &decrypt_msg(encrypted, secret2)?);
        Ok(())
    }
}
