use serde::Serialize;
use std::fmt::Debug;

pub trait ContentRef: Debug + Serialize + Clone + Eq + PartialOrd + std::hash::Hash {}
impl<T: Debug + Serialize + Clone + Eq + PartialOrd + std::hash::Hash> ContentRef for T {}
