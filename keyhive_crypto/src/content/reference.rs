use core::{fmt::Debug, hash::Hash};
use serde::Serialize;

pub trait ContentRef: Debug + Serialize + Clone + Eq + PartialOrd + Hash {}
impl<T: Debug + Serialize + Clone + Eq + PartialOrd + Hash> ContentRef for T {}
