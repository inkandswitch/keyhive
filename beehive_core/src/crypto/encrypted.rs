//! Ciphertext with public metadata.

use super::siv::Siv;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// The public information for a ciphertext.
///
/// This wraps a ciphertext that includes the [`Siv`] and the type of the data
/// that was encrypted (or that the plaintext is _expected_ to be).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Encrypted<T> {
    /// The nonce used to encrypt the data.
    pub nonce: Siv,

    /// The encrypted data.
    pub ciphertext: Vec<u8>,

    /// The type of the data that was encrypted.
    _plaintext_tag: PhantomData<T>,
}

impl<T> Encrypted<T> {
    /// Associate a nonce with a ciphertext and assert the plaintext type.
    pub fn new(nonce: Siv, ciphertext: Vec<u8>) -> Encrypted<T> {
        Encrypted {
            nonce,
            ciphertext,
            _plaintext_tag: PhantomData,
        }
    }
}
