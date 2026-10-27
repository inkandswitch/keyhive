//! Error types for CGKA operations.

use crate::operation::CitationId;
use alloc::collections::BTreeSet;
use keyhive_crypto::verified::SignError;

/// Errors arising from CGKA operations.
#[derive(Debug, thiserror::Error)]
pub enum CgkaError {
    #[error("Conversion error")]
    Conversion,

    #[error("Current encrypter not found")]
    CurrentEncrypterNotFound,

    #[error("Decryption failed: {0}")]
    Decryption(alloc::string::String),

    #[error("Depth not found")]
    DepthNotFound,

    #[error("Deriving nonce failed: {0}")]
    DeriveNonce(alloc::string::String),

    #[error("Encryption failed: {0}")]
    Encryption(chacha20poly1305::Error),

    #[error("Encrypted secret not found")]
    EncryptedSecretNotFound,

    /// A path secret decrypted to a key other than its node's public key.
    #[error("A path secret does not match its node's public key")]
    PathSecretMismatch,

    #[error("Identifier not found")]
    IdentifierNotFound,

    #[error("Invalid operation")]
    InvalidOperation,

    #[error("No membership answer yet for a set of {} citations", .0.len())]
    MembershipUnknown(BTreeSet<CitationId>),

    #[error("Invalid path length")]
    InvalidPathLength,

    #[error("Group has no members")]
    NoMembers,

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

    #[error("Unexpected key conflict")]
    UnexpectedKeyConflict,

    #[error("Expected an add for invite")]
    UnexpectedInviteOperation,

    #[error("Unknown PCS key")]
    UnknownPcsKey,

    #[error("Operation belongs to a different document")]
    WrongDocument,

    #[error(transparent)]
    SigningError(#[from] SignError),
}

impl CgkaError {
    /// Whether this error indicates a missing causal dependency.
    pub fn is_missing_dependency(&self) -> bool {
        matches!(
            self,
            Self::NotInitialized
                | Self::IdentifierNotFound
                | Self::UnexpectedInviteOperation
                | Self::OutOfOrderOperation
        )
    }
}
