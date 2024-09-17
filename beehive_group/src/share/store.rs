use super::op::{Add, Replace}; // FIXME split
use crate::crypto::signed::Signed;
use std::collections::BTreeSet;

pub struct Store {
    pub additions: BTreeSet<Signed<Add>>,
    pub replacements: BTreeSet<Signed<Replace>>,
}

impl Store {
    pub fn new() -> Self {
        Store {
            additions: BTreeSet::new(),
            replacements: BTreeSet::new(),
        }
    }
}
