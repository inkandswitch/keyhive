#[derive(Debug, thiserror::Error)]
pub enum CGKAError {
    #[error("Encryption failed: {0}")]
    Encryption(chacha20poly1305::Error),

    #[error("Tree index out of bounds")]
    TreeIndexOutOfBounds,

    #[error("Identifier not found")]
    IdentifierNotFound,

    #[error("PublicKey not found")]
    PublicKeyNotFound,
}
