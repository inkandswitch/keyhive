use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmptySet<T> {
    pub head: T,
    pub rest: BTreeSet<T>,
}

impl<T> NonEmptySet<T> {
    pub fn len(&self) -> usize {
        self.rest.len() + 1
    }
}

impl<T: Ord> IntoIterator for NonEmptySet<T> {
    type Item = T;
    type IntoIter = <BTreeSet<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        BTreeSet::from(self).into_iter()
    }
}

impl<T: Ord> From<NonEmptySet<T>> for BTreeSet<T> {
    fn from(ne_set: NonEmptySet<T>) -> Self {
        let mut set = ne_set.rest;
        set.insert(ne_set.head);
        set
    }
}
