use crate::access::Access;
use crate::crypto::{Encrypted, Signed};
use crate::hash::Hash;
use crate::principal::agent::Agent;
use chacha20poly1305::AeadInPlace;
use std::collections::{BTreeMap, BTreeSet};

pub struct Group<'a> {
    pub id: [u8; 32],
    pub members: BTreeMap<&'a Agent, Access>,
}

// FIXME Placeholder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaChaKey {
    bytes: [u8; 32],
}

pub struct Ciphertext {
    bytes: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SharingPublicKey {
    key: x25519_dalek::PublicKey,
}

impl PartialOrd for SharingPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.key.as_bytes().partial_cmp(other.key.as_bytes())
    }
}

impl Ord for SharingPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.as_bytes().cmp(other.key.as_bytes())
    }
}

pub fn dcgka_2m_broadcast(
    key: &XChaChaKey,
    sharer_key: &x25519_dalek::StaticSecret,
    public_keys: BTreeSet<&SharingPublicKey>,
) -> BTreeMap<SharingPublicKey, Encrypted<chacha20poly1305::XChaCha20Poly1305>> {
    let mut wrapped_key_map = BTreeMap::new();

    for pk in public_keys {
        let shared_secret: x25519_dalek::SharedSecret = sharer_key.diffie_hellman(&pk.key);
        // FIXME convert shared secret to bytes
        // encrypt payload

        // let generic_arr:  = generic_array::GenericArray::from_slice(shared_secret.as_bytes());

        let chacha_key: chacha20poly1305::XChaCha20Poly1305 =
            // FIXME prefer fixed size key with ::new(key: Key)
            chacha20poly1305::KeyInit::new_from_slice(shared_secret.as_bytes())
                .expect("FIXME");

        let nonce = chacha20poly1305::XNonce::from_slice(&[0u8; 24]);

        let mut key_clone = key.clone();

        let mut bytes = chacha_key
            .encrypt_in_place_detached(nonce, &[], &mut key_clone.bytes)
            .expect("FIXME")
            .to_vec();

        bytes.append(&mut key.bytes.to_vec());

        let wrapped_key: Encrypted<chacha20poly1305::XChaCha20Poly1305> = Encrypted {
            ciphertext: bytes,
            _phantom: std::marker::PhantomData,
        };

        wrapped_key_map.insert(*pk, wrapped_key);
    }

    wrapped_key_map
}

pub struct SetReadKeyOp {
    pub set_read_key: x25519_dalek::StaticSecret,
    pub parents: BTreeSet<Hash<Signed<SetReadKeyOp>>>,
}

// pub struct MyPubKey {
//     pub read_key_ops: Signed<MyReadKeyOps>,
// }

// IDB
pub struct MyReadKeyOps {
    // FIXME use a single signture?
    pub cold_call_ops: BTreeSet<SetReadKeyOp>,
    pub for_group_ops: BTreeMap<ed25519_dalek::VerifyingKey, BTreeSet<SetReadKeyOp>>,
}

pub struct MyReadKeyState {
    pub cold_call: x25519_dalek::StaticSecret,
    pub for_group: BTreeMap<ed25519_dalek::VerifyingKey, x25519_dalek::StaticSecret>,
}

pub struct Art {
    pub members: BTreeSet<ed25519_dalek::VerifyingKey>,
    pub materialized_tree: ArtNode,
}

pub struct ArtNode {
    pub pk: x25519_dalek::PublicKey,

    pub left: Option<Box<ArtNode>>,
    pub right: Option<Box<ArtNode>>,
}

impl ArtNode {
    pub fn replace(
        &mut self,
        stale: &x25519_dalek::PublicKey,
        fresh_pk: &x25519_dalek::PublicKey,
        fresh_sk: &x25519_dalek::StaticSecret,
    ) -> () {
        if self.pk == *stale {
            self.pk = *fresh_pk;
        }

        if let Some(left) = &mut self.left {
            left.replace(stale, fresh_pk, fresh_sk);
        }

        if let Some(right) = &mut self.right {
            right.replace(stale, fresh_pk, fresh_sk);
        }
    }
}
