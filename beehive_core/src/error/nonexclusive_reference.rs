use thiserror::Error;

/// Nonexclusive reference error.
///
/// This is useful for when trying to unwrap an [`Rc`]
/// that may have other strong references.
///
/// [`Rc`]: std::rc::Rc
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[error("Nonexclusive reference")]
pub struct NonexclusiveReferenceError<'a, T>(pub &'a T);
