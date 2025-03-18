use serde::Serialize;
use std::{fmt::Debug, hash::Hash};

pub trait ContentRef: Debug + Serialize + Clone + Eq + PartialOrd + Hash {}
impl<T: Debug + Serialize + Clone + Eq + PartialOrd + Hash> ContentRef for T {}
