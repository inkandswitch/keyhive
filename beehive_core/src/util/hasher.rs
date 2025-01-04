use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

pub(crate) fn signing_key<H: Hasher>(signing_key: &ed25519_dalek::SigningKey, state: &mut H) {
    std::hash::Hash::hash(signing_key.to_bytes().as_ref(), state);
}

pub(crate) fn keys<H: Hasher, K: Hash, V>(tree: &BTreeMap<K, V>, state: &mut H) {
    for k in tree.keys() {
        std::hash::Hash::hash(k, state);
    }
}
