use dupe::Dupe;
use serde::{Serialize, Serializer};
use std::{ops::Deref, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WrappedRc<T>(pub Rc<T>);

impl<T> WrappedRc<T> {
    pub fn new(value: T) -> Self {
        WrappedRc(Rc::new(value))
    }
}

impl<T> From<Rc<T>> for WrappedRc<T> {
    fn from(rc: Rc<T>) -> Self {
        WrappedRc(rc)
    }
}

impl<T> From<WrappedRc<T>> for Rc<T> {
    fn from(wrapped_rc: WrappedRc<T>) -> Self {
        wrapped_rc.0
    }
}

impl<T: Clone> Dupe for WrappedRc<T> {
    fn dupe(&self) -> Self {
        WrappedRc(self.0.dupe())
    }
}

impl<T> Deref for WrappedRc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Serialize for WrappedRc<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
