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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyState {
    ops: CaMap<Signed<KeyOp>>,
    known_keys: HashSet<ShareKey>,
}

impl PrekeyState {
    pub fn new() -> Self {
        Self {
            ops: CaMap::new(),
            known_keys: HashSet::new(),
        }
    }

    pub fn from_iter(
        iter: impl IntoIterator<Item = Signed<KeyOp>>,
    ) -> Result<Self, MissingDependency<ShareKey>> {
        let mut s = Self::new();

        for op in iter {
            s.insert_op(op)?;
        }

        Ok(s)
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        signing_key: &ed25519_dalek::SigningKey,
        size: usize,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let (ops, known_keys) = (0..size).try_fold(
            (CaMap::new(), HashSet::new()),
            |(mut ops, mut known_keys), _| {
                let secret_key = ShareSecretKey::generate(csprng);
                let share_key = secret_key.share_key();

                let op = Signed::try_sign(KeyOp::add(share_key), &signing_key)?;
                ops.insert(op.into());
                known_keys.insert(share_key);

                Ok::<_, SigningError>((ops, known_keys))
            },
        )?;

        Ok(Self { ops, known_keys })
    }

    pub fn ops(&self) -> &CaMap<Signed<KeyOp>> {
        &self.ops
    }

    pub fn known_keys(&self) -> &HashSet<ShareKey> {
        &self.known_keys
    }

    pub fn insert_op(&mut self, op: Signed<KeyOp>) -> Result<(), MissingDependency<ShareKey>> {
        match op.payload() {
            KeyOp::Add(inner) => {
                self.known_keys.insert(inner.share_key);
                self.ops.insert(Rc::new(op));
            }
            KeyOp::Rotate(RotateKeyOp { old, new }) => {
                if !self.contains_share_key(old) {
                    return Err(MissingDependency(*old));
                }

                self.known_keys.insert(*new);
                self.ops.insert(Rc::new(op));
            }
        }

        Ok(())
    }

    pub fn contains_share_key(&self, key: &ShareKey) -> bool {
        self.known_keys.contains(key)
    }

    pub fn rotate(
        &mut self,
        old: ShareKey,
        new: ShareKey,
        signer: &ed25519_dalek::SigningKey,
    ) -> Result<ShareKey, SigningError> {
        let op = Signed::try_sign(KeyOp::rotate(old, new), signer)?;

        self.known_keys.insert(new);
        self.ops.insert(op.into());

        Ok(new)
    }

    pub fn rotate_gen<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old: ShareKey,
        signer: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        self.rotate(old, new_secret.share_key(), signer)
    }

    pub fn expand<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        signer: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new = new_secret.share_key();
        let op = Signed::try_sign(KeyOp::add(new), signer)?;

        self.known_keys.insert(new);
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

impl std::hash::Hash for PrekeyState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ops.hash(state);
        self.known_keys.iter().collect::<Vec<_>>().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test_utils")]
    #[test]
    fn test_materialization() {
        /*
         *                     ┌─────────────┐
         *                     │ share_key_5 │
         *                     └─────────────┘
         *                            │
         *                            │
         *                            ▼
         * ┌─────────────┐      ┌─────────────┐
         * │ share_key_3 │      │ share_key_4 │
         * └─────────────┘      └─────────────┘
         *        │                    │
         *        │                    │
         *        │   ┌─────────────┐  │  ┌─────────────┐
         *        └──▶│ share_key_1 │◀─┘  │ share_key_2 │
         *            └─────────────┘     └─────────────┘
         *                   │                  │
         *                   │                  │
         *                   │  ┌────────────┐  │
         *                   └─▶│   (None)   │◀─┘
         *                      └────────────┘
         */

        let mut state = PrekeyState::new();

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let share_key_1 = ShareKey::generate(&mut rand::thread_rng());
        let share_key_2 = ShareKey::generate(&mut rand::thread_rng());
        let share_key_3 = ShareKey::generate(&mut rand::thread_rng());
        let share_key_4 = ShareKey::generate(&mut rand::thread_rng());
        let share_key_5 = ShareKey::generate(&mut rand::thread_rng());

        let op1 = Signed::try_sign(KeyOp::add(share_key_1), &signing_key).unwrap();
        let op2 = Signed::try_sign(KeyOp::add(share_key_2), &signing_key).unwrap();

        let op3 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_3), &signing_key).unwrap();
        let op4 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_4), &signing_key).unwrap();

        let op5 = Signed::try_sign(KeyOp::rotate(share_key_4, share_key_5), &signing_key).unwrap();

        state.insert_op(op1).unwrap();
        state.insert_op(op2).unwrap();
        state.insert_op(op3).unwrap();
        state.insert_op(op4).unwrap();
        state.insert_op(op5).unwrap();

        let materialized = state.materialize();
        assert_eq!(materialized.len(), 3);
        assert!(materialized.contains(&share_key_2));
        assert!(materialized.contains(&share_key_3));
        assert!(materialized.contains(&share_key_5));
    }
}
