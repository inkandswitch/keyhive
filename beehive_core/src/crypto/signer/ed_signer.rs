use super::super::signed::{Signed, SigningError};
use crate::principal::verifiable::Verifiable;
use dupe::Dupe;
use serde::Serialize;
use std::hash::Hash;

pub trait EdSigner:
    ed25519_dalek::Signer<ed25519_dalek::Signature>
    + Verifiable
    + Dupe
    + Hash
    + PartialEq
    + Eq
    + From<ed25519_dalek::SigningKey>
{
    fn try_seal<T: Serialize>(&self, payload: T) -> Result<Signed<T>, SigningError> {
        Signed::try_sign(payload, self)
    }
}
