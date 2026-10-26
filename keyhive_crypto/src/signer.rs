//! Signer traits and implementations.

pub mod async_signer;
pub mod ephemeral;
pub mod memory;
pub mod sync_signer;

use crate::identifier::InvalidIdentifier;

/// Why a signer could not sign.
#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    #[error("The signer's key cannot be an issuer: {0}")]
    InvalidIssuer(#[from] InvalidIdentifier),
}

/// Why a signer could not sign.
#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub enum SigningError {
    SigningFailed(ed25519_dalek::SignatureError),
    InvalidIssuer(InvalidIdentifier),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SigningFailed(e) => write!(f, "Signing failed: {e}"),
            Self::InvalidIssuer(e) => write!(f, "The signer's key cannot be an issuer: {e}"),
        }
    }
}

// No `source`: `signature::Error` implements `Error` only under `std`.
// `Display` includes it.
#[cfg(not(feature = "std"))]
impl core::error::Error for SigningError {}

#[cfg(not(feature = "std"))]
impl From<InvalidIdentifier> for SigningError {
    fn from(e: InvalidIdentifier) -> Self {
        Self::InvalidIssuer(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<ed25519_dalek::SignatureError> for SigningError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::SigningFailed(e)
    }
}
