use crate::crypto::signed::SigningError;

#[derive(Debug, thiserror::Error)]
pub enum CgkaError {
    #[error("Conversion error")]
    Conversion,

    #[error("Current encrypter not found")]
    CurrentEncrypterNotFound,

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Deriving nonce failed: {0}")]
    DeriveNonce(String),

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

    #[error("Cgka is not initialized")]
    NotInitialized,

    #[error("Operation not found")]
    OperationNotFound,

    #[error("Operation was not received in causal order")]
    OutOfOrderOperation,

    #[error("Owner Identifier not found")]
    OwnerIdentifierNotFound,

    #[error("ShareKey not found")]
    ShareKeyNotFound,

    #[error("SecretKey not found")]
    SecretKeyNotFound,

    #[error("Tried to remove last member from group")]
    RemoveLastMember,

    #[error("Serialization failed: {0}")]
    Serialize(String),

    #[error("Unexpected key conflict")]
    UnexpectedKeyConflict,

    #[error("Expected CgkaOperation::Add for initial operation")]
    UnexpectedInitialOperation,

    #[error("Expected CgkaOperation::Add for invite")]
    UnexpectedInviteOperation,

    #[error("Unknown PCS key")]
    UnknownPcsKey,

    #[error(transparent)]
    SigningError(#[from] SigningError),
}

impl CgkaError {
    pub fn is_missing_dependency(&self) -> bool {
        matches!(
            self,
            Self::NotInitialized
                | Self::IdentifierNotFound
                | Self::UnexpectedInitialOperation
                | Self::UnexpectedInviteOperation
                | Self::OutOfOrderOperation
        )
    }
}
