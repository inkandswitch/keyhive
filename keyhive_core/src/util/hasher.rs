use std::{
    collections::{BTreeSet, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

pub(crate) fn hash_set<H: Hasher, K: Hash>(tree: &HashSet<K>, state: &mut H) {
    tree.iter()
        .map(|k| {
            let mut s = DefaultHasher::new();
            k.hash(&mut s);
            s.finish()
        })
        .collect::<BTreeSet<u64>>()
        .hash(state);
}
