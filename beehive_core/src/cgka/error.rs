#[derive(Debug, thiserror::Error)]
pub enum CGKAError {
    // FIXME: This is a placeholder to get things to compile
    #[error("Conversion failed")]
    Conversion,

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Encryption failed: {0}")]
    Encryption(chacha20poly1305::Error),

    #[error("Identifier not found")]
    IdentifierNotFound,

    #[error("No root key")]
    NoRootKey,

    #[error("Owner Identifier not found")]
    OwnerIdentifierNotFound,

    #[error("PublicKey not found")]
    PublicKeyNotFound,

    #[error("Tried to remove last member from group")]
    RemoveLastMember,

    #[error("Tree index out of bounds")]
    TreeIndexOutOfBounds,
}
