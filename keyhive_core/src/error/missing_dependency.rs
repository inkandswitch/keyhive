use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[error("Missing dependency: {0}")]
pub struct MissingDependency<T>(pub T);
