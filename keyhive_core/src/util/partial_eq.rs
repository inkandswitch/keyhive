use crate::crypto::share_key::{ShareKey, ShareSecretKey};
use std::collections::BTreeMap;

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
