use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// A representation of a [`Vec`] that's already in the reverse of an expected order,
/// e.g., for efficient pop operations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reversed<T>(pub Vec<T>);

impl<T> Reversed<T> {
    /// Consumes self and returns the underlying Vec
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T> Deref for Reversed<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Reversed<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> From<Vec<T>> for Reversed<T> {
    fn from(vec: Vec<T>) -> Self {
        Self(vec)
    }
}

impl<T> IntoIterator for Reversed<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
