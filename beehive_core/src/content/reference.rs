use serde::Serialize;

// FIMXE implement for Blake3, Sha3, AutomergeIds etc
pub trait ContentRef: Serialize + Clone + Eq + PartialOrd + std::hash::Hash {}
impl<T: Serialize + Clone + Eq + PartialOrd + std::hash::Hash> ContentRef for T {}
