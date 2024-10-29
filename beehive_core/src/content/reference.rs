use serde::Serialize;
use std::fmt::Debug;

// FIXME implement for Blake3, Sha3, AutomergeIds etc
pub trait ContentRef: Debug + Serialize + Clone + Eq + PartialOrd + std::hash::Hash {}
impl<T: Debug + Serialize + Clone + Eq + PartialOrd + std::hash::Hash> ContentRef for T {}
