use crate::crypto::share_key::{ShareKey, ShareSecretKey};
use std::{collections::BTreeMap, fmt::Debug};

pub(crate) fn prekey_fmt(
    prekey_pairs: &BTreeMap<ShareKey, ShareSecretKey>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    Debug::fmt(&prekey_pairs.keys(), f)
}
