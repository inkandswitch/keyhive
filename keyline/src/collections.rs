//! Conditional collection types that use `HashMap`/`HashSet` when `std` is enabled,
//! and fall back to `BTreeMap`/`BTreeSet` for `no_std` environments.

#[cfg(feature = "std")]
mod inner {
    pub use std::collections::{hash_map::Entry, HashMap as Map, HashSet as Set};
}

#[cfg(not(feature = "std"))]
mod inner {
    pub use alloc::collections::{btree_map::Entry, BTreeMap as Map, BTreeSet as Set};
}

pub use inner::{Entry, Map, Set};
