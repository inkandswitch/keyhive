#[derive(Debug, thiserror::Error)]
pub enum CGKAError {
    #[error("Tree index out of bounds")]
    TreeIndexOutOfBounds,

    #[error("Identifier not found")]
    IdentifierNotFound,
}
