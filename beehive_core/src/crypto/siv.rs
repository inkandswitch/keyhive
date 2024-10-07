use crate::principal::document::Document;
use chacha20poly1305::KeyInit;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use std::io::Read;

pub struct Key(pub [u8; 32]);

impl From<Key> for chacha20poly1305::XChaCha20Poly1305 {
    fn from(key: Key) -> Self {
        chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key.0).expect("FIXME")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Siv(pub [u8; 24]);

impl Siv {
    pub fn new(key: [u8; 32], content: &[u8], doc: &Document) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"automerge/beehive"); // FIXME need these?
        hasher.update(doc.id().as_bytes());
        hasher.update(&key);
        hasher.update(content);

        let mut buf = [0; 24];
        hasher
            .finalize_xof()
            .take(24)
            .read(&mut buf)
            .expect("FIXME");

        Siv(buf)
    }

    pub fn as_xnonce(&self) -> chacha20poly1305::XNonce {
        chacha20poly1305::XNonce::from_slice(&self.0).clone()
    }
}

impl From<Siv> for [u8; 24] {
    fn from(siv: Siv) -> Self {
        siv.0
    }
}

impl From<[u8; 24]> for Siv {
    fn from(arr: [u8; 24]) -> Self {
        Siv(arr)
    }
}

impl From<Siv> for chacha20poly1305::XNonce {
    fn from(siv: Siv) -> Self {
        Self::from_slice(&siv.0).clone()
    }
}

impl From<chacha20poly1305::XNonce> for Siv {
    fn from(nonce: chacha20poly1305::XNonce) -> Self {
        Siv(nonce.into())
    }
}
