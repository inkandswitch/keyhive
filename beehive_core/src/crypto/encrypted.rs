use super::siv::Siv;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Encrypted<T> {
    pub nonce: Siv,
    // FIXME pub additional_data?
    pub ciphertext: Vec<u8>,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> Encrypted<T> {
    pub fn new(nonce: Siv, ciphertext: Vec<u8>) -> Encrypted<T> {
        Encrypted {
            nonce,
            ciphertext,
            _phantom: PhantomData,
        }
    }
}
