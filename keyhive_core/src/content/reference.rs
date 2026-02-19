use serde::Serialize;
use std::{fmt::Debug, hash::Hash};

pub trait ContentRef: Debug + Serialize + Clone + Eq + PartialOrd + Hash + Send + Sync {}
impl<T: Debug + Serialize + Clone + Eq + PartialOrd + Hash + Send + Sync> ContentRef for T {}
