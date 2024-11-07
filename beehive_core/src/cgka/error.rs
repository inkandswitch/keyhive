#[derive(Debug, thiserror::Error)]
pub enum CgkaError {
    #[error("Conversion error")]
    Conversion,

    #[error("Current encrypter not found")]
    CurrentEncrypterNotFound,

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Encryption failed: {0}")]
    Encryption(chacha20poly1305::Error),

    #[error("Encrypted secret not found")]
    EncryptedSecretNotFound,

    #[error("Identifier not found")]
    IdentifierNotFound,

    #[error("Invalid operation")]
    InvalidOperation,

    #[error("Invalid path length")]
    InvalidPathLength,

    #[error("No root key")]
    NoRootKey,

    #[error("Operation not found")]
    OperationNotFound,

    #[error("Owner Identifier not found")]
    OwnerIdentifierNotFound,

    #[error("PublicKey not found")]
    PublicKeyNotFound,

    #[error("SecretKey not found")]
    SecretKeyNotFound,

    #[error("Tried to remove last member from group")]
    RemoveLastMember,

    #[error("Serialization failed: {0}")]
    Serialize(String),

    #[error("Tree index out of bounds")]
    TreeIndexOutOfBounds,

    #[error("Unexpected key conflict")]
    UnexpectedKeyConflict,
}
