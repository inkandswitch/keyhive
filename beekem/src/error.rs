//! Error types for CGKA operations.

use keyhive_crypto::signed::SigningError;

/// Errors arising from CGKA operations.
#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum CgkaError {
    #[cfg_attr(feature = "thiserror", error("Conversion error"))]
    Conversion,

    #[cfg_attr(feature = "thiserror", error("Current encrypter not found"))]
    CurrentEncrypterNotFound,

    #[cfg_attr(feature = "thiserror", error("Decryption failed: {0}"))]
    Decryption(alloc::string::String),

    #[cfg_attr(feature = "thiserror", error("Deriving nonce failed: {0}"))]
    DeriveNonce(alloc::string::String),

    #[cfg_attr(feature = "thiserror", error("Encryption failed: {0}"))]
    Encryption(chacha20poly1305::Error),

    #[cfg_attr(feature = "thiserror", error("Encrypted secret not found"))]
    EncryptedSecretNotFound,

    #[cfg_attr(feature = "thiserror", error("Identifier not found"))]
    IdentifierNotFound,

    #[cfg_attr(feature = "thiserror", error("Invalid operation"))]
    InvalidOperation,

    #[cfg_attr(feature = "thiserror", error("Invalid path length"))]
    InvalidPathLength,

    #[cfg_attr(feature = "thiserror", error("No root key"))]
    NoRootKey,

    #[cfg_attr(feature = "thiserror", error("Cgka is not initialized"))]
    NotInitialized,

    #[cfg_attr(feature = "thiserror", error("Operation not found"))]
    OperationNotFound,

    #[cfg_attr(
        feature = "thiserror",
        error("Operation was not received in causal order")
    )]
    OutOfOrderOperation,

    #[cfg_attr(feature = "thiserror", error("Owner Identifier not found"))]
    OwnerIdentifierNotFound,

    #[cfg_attr(feature = "thiserror", error("ShareKey not found"))]
    ShareKeyNotFound,

    #[cfg_attr(feature = "thiserror", error("SecretKey not found"))]
    SecretKeyNotFound,

    #[cfg_attr(feature = "thiserror", error("Tried to remove last member from group"))]
    RemoveLastMember,

    #[cfg_attr(feature = "thiserror", error("Serialization failed: {0}"))]
    Serialize(alloc::string::String),

    #[cfg_attr(feature = "thiserror", error("Unexpected key conflict"))]
    UnexpectedKeyConflict,

    #[cfg_attr(
        feature = "thiserror",
        error("Expected CgkaOperation::Add for initial operation")
    )]
    UnexpectedInitialOperation,

    #[cfg_attr(feature = "thiserror", error("Expected CgkaOperation::Add for invite"))]
    UnexpectedInviteOperation,

    #[cfg_attr(feature = "thiserror", error("Unknown PCS key"))]
    UnknownPcsKey,

    #[cfg_attr(feature = "thiserror", error(transparent))]
    SigningError(#[cfg_attr(feature = "thiserror", from)] SigningError),
}

#[cfg(not(feature = "thiserror"))]
impl core::fmt::Display for CgkaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Conversion => write!(f, "Conversion error"),
            Self::CurrentEncrypterNotFound => write!(f, "Current encrypter not found"),
            Self::Decryption(msg) => write!(f, "Decryption failed: {msg}"),
            Self::DeriveNonce(msg) => write!(f, "Deriving nonce failed: {msg}"),
            Self::Encryption(e) => write!(f, "Encryption failed: {e}"),
            Self::EncryptedSecretNotFound => write!(f, "Encrypted secret not found"),
            Self::IdentifierNotFound => write!(f, "Identifier not found"),
            Self::InvalidOperation => write!(f, "Invalid operation"),
            Self::InvalidPathLength => write!(f, "Invalid path length"),
            Self::NoRootKey => write!(f, "No root key"),
            Self::NotInitialized => write!(f, "Cgka is not initialized"),
            Self::OperationNotFound => write!(f, "Operation not found"),
            Self::OutOfOrderOperation => {
                write!(f, "Operation was not received in causal order")
            }
            Self::OwnerIdentifierNotFound => write!(f, "Owner Identifier not found"),
            Self::ShareKeyNotFound => write!(f, "ShareKey not found"),
            Self::SecretKeyNotFound => write!(f, "SecretKey not found"),
            Self::RemoveLastMember => write!(f, "Tried to remove last member from group"),
            Self::Serialize(msg) => write!(f, "Serialization failed: {msg}"),
            Self::UnexpectedKeyConflict => write!(f, "Unexpected key conflict"),
            Self::UnexpectedInitialOperation => {
                write!(f, "Expected CgkaOperation::Add for initial operation")
            }
            Self::UnexpectedInviteOperation => {
                write!(f, "Expected CgkaOperation::Add for invite")
            }
            Self::UnknownPcsKey => write!(f, "Unknown PCS key"),
            Self::SigningError(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(not(feature = "thiserror"))]
impl From<SigningError> for CgkaError {
    fn from(e: SigningError) -> Self {
        Self::SigningError(e)
    }
}

impl CgkaError {
    /// Whether this error indicates a missing causal dependency.
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
