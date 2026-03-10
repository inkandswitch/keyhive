//! Fork/merge traits for transactional operations.

/// Synchronously fork a data structure.
pub trait Fork {
    /// The forked variant of the data structure.
    type Forked;

    /// Fork the data structure.
    fn fork(&self) -> Self::Forked;
}

/// Synchronously merge a fork back into its original data structure.
pub trait Merge: Fork {
    /// Consume the fork and merge it back into the original data structure.
    fn merge(&mut self, fork: Self::Forked);
}
