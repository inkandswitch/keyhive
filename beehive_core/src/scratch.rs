use crate::crypto::{
    digest::Digest, encrypted::Encrypted, share_key::ShareKey, signed::Signed, siv::Siv,
    symmetric_key::SymmetricKey,
};
use crate::principal::document::Document;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

pub fn dcgka_2m_broadcast<'a, T: Serialize>(
    key: &SymmetricKey,
    doc: &Document<'a, T>,
    sharer_key: &x25519_dalek::StaticSecret,
    public_keys: HashSet<&ShareKey>,
) -> BTreeMap<ShareKey, Encrypted<chacha20poly1305::XChaCha20Poly1305>> {
    let mut wrapped_key_map = BTreeMap::new();

    for pk in public_keys {
        let shared_secret: x25519_dalek::SharedSecret = sharer_key.diffie_hellman(&pk.0);
        let shared_key = SymmetricKey::from(shared_secret.as_bytes());

        let nonce = Siv::new(&shared_key, &key.0, doc);

        let mut bytes = shared_key
            .encrypt(nonce, &[])
            .expect("FIXME temp function")
            .to_vec();
        bytes.append(&mut key.0.to_vec());

        let wrapped_key: Encrypted<chacha20poly1305::XChaCha20Poly1305> =
            Encrypted::new(nonce, bytes);

        wrapped_key_map.insert(*pk, wrapped_key);
    }

    wrapped_key_map
}

#[derive(Clone, Serialize)]
pub struct SetReadKeyOp {
    pub set_read_key: x25519_dalek::StaticSecret,
    pub parents: HashSet<Digest<Signed<SetReadKeyOp>>>,
}

#[derive(Clone, Serialize)]
pub struct MyReadKeyOps {
    // FIXME use a single signture?
    pub cold_call_ops: HashSet<SetReadKeyOp>,
    pub for_group_ops: BTreeMap<ed25519_dalek::VerifyingKey, HashSet<SetReadKeyOp>>,
}

pub struct MyReadKeyState {
    pub cold_call: x25519_dalek::StaticSecret,
    pub for_group: BTreeMap<ed25519_dalek::VerifyingKey, x25519_dalek::StaticSecret>,
}

pub struct Art {
    pub members: HashSet<ed25519_dalek::VerifyingKey>,
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
