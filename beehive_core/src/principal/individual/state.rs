use super::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp};
use crate::{
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
    },
    error::missing_dependency::MissingDependency,
    util::content_addressed_map::CaMap,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, rc::Rc};

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrekeyState {
    pub ops: CaMap<Signed<KeyOp>>,
}

impl PrekeyState {
    pub fn new() -> Self {
        Self { ops: CaMap::new() }
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        signing_key: &ed25519_dalek::SigningKey,
        size: usize,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let ops = (0..size).try_fold(CaMap::new(), |mut ops, _| {
            let secret_key = ShareSecretKey::generate(csprng);
            let share_key = secret_key.share_key();

            let op = Signed::try_sign(KeyOp::add(share_key), &signing_key)?;
            ops.insert(op.into());

            Ok::<_, SigningError>(ops)
        })?;

        Ok(Self { ops })
    }

    pub fn receive_op(&mut self, op: Signed<KeyOp>) -> Result<(), MissingDependency<ShareKey>> {
        match op.payload() {
            KeyOp::Add(_) => {
                self.ops.insert(Rc::new(op));
            }
            KeyOp::Rotate(RotateKeyOp { old, .. }) => {
                if self.contains_key(old) {
                    self.ops.insert(Rc::new(op));
                } else {
                    return Err(MissingDependency(*old));
                }
            }
        }

        Ok(())
    }

    pub fn contains_key(&self, key: &ShareKey) -> bool {
        self.ops.values().any(|signed| match signed.payload() {
            KeyOp::Add(AddKeyOp { share_key }) => share_key == key,
            KeyOp::Rotate(RotateKeyOp { new, .. }) => new == key,
        })
    }

    pub fn rotate<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old: ShareKey,
        signer: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new = new_secret.share_key();
        let op = Signed::try_sign(KeyOp::rotate(old, new), signer)?;

        self.ops.insert(op.into());

        Ok(new)
    }

    pub fn expand<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        signer: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new = new_secret.share_key();
        let op = Signed::try_sign(KeyOp::add(new), signer)?;

        self.ops.insert(op.into());

        Ok(new)
    }

    pub fn materialize(&self) -> HashSet<ShareKey> {
        let mut keys = HashSet::new();
        let mut to_drop = vec![];

        for signed in self.ops.values() {
            match signed.payload() {
                KeyOp::Add(AddKeyOp { share_key }) => {
                    keys.insert(*share_key);
                }
                KeyOp::Rotate(RotateKeyOp { old, new }) => {
                    to_drop.push(old);
                    keys.insert(*new);
                }
            }
        }

        for tombstone in to_drop {
            keys.remove(tombstone);
        }

        keys
    }
}
