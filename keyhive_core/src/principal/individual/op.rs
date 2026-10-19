//! Operations for updating prekeys.

pub mod add_key;
pub mod rotate_key;

use self::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
use crate::util::content_addressed_map::CaMap;
use derive_more::{From, TryInto};
use dupe::Dupe;
use ed25519_dalek::{Signature, VerifyingKey};
use keyhive_crypto::{
    identifier::Identifier,
    share_key::ShareKey,
    verifiable::Verifiable,
    verified::{Signed, Verified, VerifyError},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

/// Operations for updating prekeys, verified.
///
/// A `KeyOp` holds a [`Verified`] statement, so a prekey operation whose
/// signature was never checked against its issuer cannot reach a prekey
/// state. One arrives as a [`SignedKeyOp`] and becomes a `KeyOp` only through
/// [`SignedKeyOp::verify`]; deserializing one verifies it too.
///
/// Note that the number of keys only ever increases.
/// This prevents the case where all keys are removed and the user is unable to be
/// added to a [`Cgka`][crate::cgka::Cgka].
#[derive(Debug, Clone, PartialEq, Eq, Hash, From, TryInto, Serialize, Deserialize)]
#[serde(into = "SignedKeyOp", try_from = "SignedKeyOp")]
pub enum KeyOp {
    /// Add a new key.
    Add(Verified<AddKeyOp>),

    /// Retire and replace an existing key.
    Rotate(Verified<RotateKeyOp>),
}

impl KeyOp {
    pub fn new_key(&self) -> &ShareKey {
        match self {
            KeyOp::Add(add) => &add.payload().share_key,
            KeyOp::Rotate(rot) => &rot.payload().new,
        }
    }

    /// Who signed it: the individual whose prekeys it changes.
    pub fn issuer(&self) -> Identifier {
        match self {
            KeyOp::Add(add) => add.issuer(),
            KeyOp::Rotate(rot) => rot.issuer(),
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            KeyOp::Add(add) => add.signed().signature(),
            KeyOp::Rotate(rot) => rot.signed().signature(),
        }
    }

    /// The signed form, for sending.
    pub fn signed(&self) -> SignedKeyOp {
        match self {
            KeyOp::Add(add) => SignedKeyOp::Add(Signed::clone(add.signed())),
            KeyOp::Rotate(rot) => SignedKeyOp::Rotate(Signed::clone(rot.signed())),
        }
    }
}

/// Cheap: a [`Verified`] shares its signed form.
impl Dupe for KeyOp {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl Verifiable for KeyOp {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            KeyOp::Add(add) => add.verifying_key(),
            KeyOp::Rotate(rot) => rot.verifying_key(),
        }
    }
}

impl From<KeyOp> for SignedKeyOp {
    fn from(op: KeyOp) -> Self {
        op.signed()
    }
}

impl TryFrom<SignedKeyOp> for KeyOp {
    type Error = VerifyError;

    fn try_from(signed: SignedKeyOp) -> Result<Self, Self::Error> {
        signed.verify()
    }
}

/// A prekey operation as received, not yet verified.
#[derive(Debug, Clone, PartialEq, Eq, From, Serialize, Deserialize)]
pub enum SignedKeyOp {
    /// Add a new key.
    Add(Signed<AddKeyOp>),

    /// Retire and replace an existing key.
    Rotate(Signed<RotateKeyOp>),
}

impl SignedKeyOp {
    /// Who claims to have signed it. Not checked until [`SignedKeyOp::verify`].
    pub fn issuer(&self) -> Identifier {
        match self {
            SignedKeyOp::Add(add) => add.issuer(),
            SignedKeyOp::Rotate(rot) => rot.issuer(),
        }
    }

    /// Decode the payload and check the signature against the issuer.
    pub fn verify(self) -> Result<KeyOp, VerifyError> {
        Ok(match self {
            SignedKeyOp::Add(add) => KeyOp::Add(add.verify()?),
            SignedKeyOp::Rotate(rot) => KeyOp::Rotate(rot.verify()?),
        })
    }
}

/// Key ops grouped by the identifier they belong to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOps(HashMap<Identifier, Vec<Arc<KeyOp>>>);

impl KeyOps {
    /// The ops belonging to `id`.
    pub fn get(&self, id: &Identifier) -> Option<&[Arc<KeyOp>]> {
        self.0.get(id).map(Vec::as_slice)
    }

    /// The identifiers that have ops.
    pub fn keys(&self) -> impl Iterator<Item = &Identifier> {
        self.0.keys()
    }

    /// The ops for each identifier.
    pub fn values(&self) -> impl Iterator<Item = &[Arc<KeyOp>]> {
        self.0.values().map(Vec::as_slice)
    }
}

impl From<HashMap<Identifier, CaMap<KeyOp>>> for KeyOps {
    fn from(by_id: HashMap<Identifier, CaMap<KeyOp>>) -> Self {
        KeyOps(
            by_id
                .into_iter()
                .map(|(id, ops)| (id, ops.into_values().collect()))
                .collect(),
        )
    }
}

impl IntoIterator for KeyOps {
    type Item = (Identifier, Vec<Arc<KeyOp>>);
    type IntoIter = std::collections::hash_map::IntoIter<Identifier, Vec<Arc<KeyOp>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Reachable prekey ops for all principals, with shared storage.
///
/// Instead of duplicating key ops across principals, the ops are stored
/// once in `ops` and each principal has an index into that shared map.
#[derive(Debug)]
pub struct AllReachablePrekeyOps {
    /// Key ops per identifier, computed once.
    pub ops: KeyOps,

    /// For each principal: the set of identifiers whose ops in `ops` are reachable, plus
    /// members it can no longer reach whose keys still help verify the history it is
    /// sent.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

impl AllReachablePrekeyOps {
    /// Returns the set of principal identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable [`KeyOp`]s for the given principal
    /// (flattened across all source identifiers), or `None` if the principal is not
    /// in the index.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<impl Iterator<Item = &Arc<KeyOp>>> {
        self.index
            .get(agent_id)
            .map(|ids| ids.iter().filter_map(|id| self.ops.get(id)).flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhive_codec::{
        error::DecodeError,
        laws::{canonical_near, round_trip, stream},
        traits::{Decode, Encode, StreamDecode},
    };
    use keyhive_crypto::{share_key::ShareSecretKey, signer::memory::MemorySigner};
    use rand::{rngs::StdRng, SeedableRng};

    fn laws<T>()
    where
        T: for<'a> arbitrary::Arbitrary<'a>
            + core::fmt::Debug
            + Encode
            + PartialEq
            + StreamDecode
            + 'static,
    {
        round_trip::<T>();
        canonical_near::<T>();
        stream::<T>();
    }

    #[test]
    fn add_key_laws() {
        laws::<AddKeyOp>();
    }

    #[test]
    fn rotate_key_laws() {
        laws::<RotateKeyOp>();
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixtures() -> (MemorySigner, AddKeyOp, RotateKeyOp) {
        let signer = MemorySigner::from(ed25519_dalek::SigningKey::from_bytes(&[7; 32]));
        let mut rng = StdRng::seed_from_u64(7);
        let mut key = || ShareSecretKey::generate(&mut rng).share_key();
        let add = AddKeyOp { share_key: key() };
        let rotate = RotateKeyOp {
            old: add.share_key,
            new: key(),
        };
        (signer, add, rotate)
    }

    /// Pins the frame of one add and one rotation signed by a fixed key: the
    /// `KH` tag, the kind (`P`, `T`), version 0, the issuer, the length, the
    /// payload and the signature. Changing the codec, the kind or the version
    /// must change this test on purpose.
    #[test]
    fn known_answer() {
        let (signer, add, rotate) = fixtures();
        let add = Verified::sign_sync(&add, &signer).expect("signs");
        let rotate = Verified::sign_sync(&rotate, &signer).expect("signs");
        assert_eq!(
            hex(add.signed().encode().as_bytes()),
            "4b485000ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea69\
             1446d22c20414862f45ddcdf54660ce2951e78dd540fb5060ffe366887286325\
             1bb0cf77588d981f5142a39189773693227dca627b81019a4c757f6bcab80b9c\
             c8704537b5c588c0184b605c6f3d4c48cdd3868315f5861c4cd145083d40b2cb\
             7fbc4ee809"
        );
        assert_eq!(
            hex(rotate.signed().encode().as_bytes()),
            "4b485400ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea69\
             1446d22c40414862f45ddcdf54660ce2951e78dd540fb5060ffe366887286325\
             1bb0cf7758547f19d4b013292048886978e9076fcc375719fb4247a7fe9edcdb\
             560a26ba688b4bd82b65ca76644632734befd3afc71801d0cb7c1ddd40e7715a\
             a2cb8094ce09699ed9d69614dc5aea6ab8963e93c2b12a6f60b06ed6fee1ad84\
             dd11224209"
        );
    }

    #[test]
    fn a_rotation_to_the_same_key_does_not_decode() {
        let (_, add, _) = fixtures();
        let same = RotateKeyOp {
            old: add.share_key,
            new: add.share_key,
        };
        assert_eq!(
            RotateKeyOp::decode(same.encode().as_bytes()),
            Err(DecodeError::InvalidField("new"))
        );
    }

    #[test]
    fn a_frame_of_one_kind_does_not_decode_as_the_other() {
        let (signer, _, rotate) = fixtures();
        let rotate = Verified::sign_sync(&rotate, &signer).expect("signs");
        let bytes = rotate.signed().encode();
        assert_eq!(
            Signed::<AddKeyOp>::decode(bytes.as_bytes()),
            Err(DecodeError::UnexpectedKind(b'T'))
        );
    }

    /// A key op serializes as its signed form, and deserializing verifies it.
    #[test]
    fn deserializing_a_key_op_verifies_it() {
        let (signer, add, _) = fixtures();
        let op = KeyOp::Add(Verified::sign_sync(&add, &signer).expect("signs"));
        let bytes = bincode::serialize(&op).expect("serializes");
        assert_eq!(bincode::deserialize::<KeyOp>(&bytes).expect("verifies"), op);

        let forged = SignedKeyOp::Add(Signed::new(
            op.issuer(),
            add.encode(),
            Signature::from_bytes(&[0; 64]),
        ));
        let bytes = bincode::serialize(&forged).expect("serializes");
        assert!(bincode::deserialize::<KeyOp>(&bytes).is_err());
    }
}
