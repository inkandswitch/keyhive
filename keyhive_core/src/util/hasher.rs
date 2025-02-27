use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

pub(crate) fn keys<H: Hasher, K: Hash, V>(tree: &BTreeMap<K, V>, state: &mut H) {
    for k in tree.keys() {
        std::hash::Hash::hash(k, state);
    }
}

pub(crate) fn hash_map_keys<H: Hasher, K: Hash + Ord, V>(tree: &HashMap<K, V>, state: &mut H) {
    tree.keys().collect::<BTreeSet<&K>>().hash(state);
}

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
