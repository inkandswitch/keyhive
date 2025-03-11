use crate::crypto::share_key::{ShareKey, ShareSecretKey};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    hash::{DefaultHasher, Hash, Hasher},
};

pub(crate) fn prekey_partial_eq(
    xs: &BTreeMap<ShareKey, ShareSecretKey>,
    ys: &BTreeMap<ShareKey, ShareSecretKey>,
) -> bool {
    xs.len() == ys.len()
        && xs
            .iter()
            .zip(ys.iter())
            .all(|((xk, xv), (yk, yv))| xk == yk && xv.to_bytes() == yv.to_bytes())
}

#[allow(dead_code)] // Not dead code; just used in a macro
pub(crate) fn hash_map_keys<K: Hash, V>(
    map1: HashMap<K, V>,
    map2: HashMap<K, V>,
) -> Option<std::cmp::Ordering> {
    let ordered1: BTreeSet<_> = map1
        .keys()
        .map(|k| {
            let mut hasher = DefaultHasher::new();
            (*k).hash(&mut hasher);
            hasher.finish()
        })
        .collect();

    let ordered2: BTreeSet<_> = map2
        .keys()
        .map(|k| {
            let mut hasher = DefaultHasher::new();
            (*k).hash(&mut hasher);
            hasher.finish()
        })
        .collect();

    ordered1.iter().partial_cmp(ordered2.iter())
}
