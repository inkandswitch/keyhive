use super::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp};
use crate::{
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError, VerificationError},
    },
    error::missing_dependency::MissingDependency,
    util::content_addressed_map::CaMap,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, rc::Rc};
use thiserror::Error;

/// Low-level prekey operation store.
///
/// # Semantics
///
/// This is essentially an OR-Set, with a small twist where we avoid the possibility
/// of having a empty set of materialized keys by replacing tombstoning with
/// rotation. The number of active prekeys can only expand, but the underlying store
/// is the same size in both cases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrekeyState {
    ops: CaMap<Signed<KeyOp>>,
}

impl PrekeyState {
    /// Create a new, empty [`PrekeyState`].
    pub fn new() -> Self {
        Self { ops: CaMap::new() }
    }

    /// Initialize a new [`PrekeyState`] from an iterator of [`Signed<KeyOp>`]s.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator of [`Signed<KeyOp>`]s.
    ///
    /// # Returns
    ///
    /// A new [`PrekeyState`] with the operations from `iter`.
    pub fn try_from_iter(
        iter: impl IntoIterator<Item = Signed<KeyOp>>,
    ) -> Result<Self, NewOpError> {
        let mut s = Self::new();

        for op in iter {
            s.insert_op(op)?;
        }

        Ok(s)
    }

    /// Initialize a [`PrekeyState`] with a set number of randomly-generated [`ShareSecretKey`]s.
    ///
    /// # Arguments
    ///
    /// * `signing_key` - The key to sign the operations with.
    /// * `size` - The number of [`ShareSecretKey`]s to generate.
    /// * `csprng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    ///
    /// A new [`PrekeyState`] with `size` [`ShareSecretKey`]s.
    ///
    /// # Errors
    ///
    /// Returns a [`SigningError`] if the operation could not be signed.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        signing_key: &ed25519_dalek::SigningKey,
        size: usize,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let ops = (0..size).try_fold(CaMap::new(), |mut ops, _| {
            let secret_key = ShareSecretKey::generate(csprng);
            let share_key = secret_key.share_key();

            let op = Signed::try_sign(KeyOp::add(share_key), signing_key)?;
            ops.insert(op.into());

            Ok::<_, SigningError>(ops)
        })?;

        Ok(Self { ops })
    }

    /// A getter for the operations in the [`PrekeyState`].
    pub fn ops(&self) -> &CaMap<Signed<KeyOp>> {
        &self.ops
    }

    /// A getter for the keys in the [`PrekeyState`].
    pub fn all_keys(&self) -> HashSet<ShareKey> {
        self.ops
            .values()
            .map(|signed| signed.payload().new_share_key())
            .collect()
    }

    /// Insert a new [`Signed<KeyOp>`] into the [`PrekeyState`].
    pub fn insert_op(&mut self, op: Signed<KeyOp>) -> Result<(), NewOpError> {
        op.try_verify()?;

        if let KeyOp::Rotate(RotateKeyOp { old, .. }) = op.payload() {
            if !self.contains_share_key(old) {
                return Err(MissingDependency(*old).into());
            }
        }

        self.ops.insert(Rc::new(op));
        Ok(())
    }

    /// Check if a [`ShareKey`] is in the [`PrekeyState`].
    pub fn contains_share_key(&self, key: &ShareKey) -> bool {
        self.ops
            .values()
            .any(|signed| signed.payload().new_share_key() == *key)
    }

    /// Rotate a [`ShareKey`] in the [`PrekeyState`].
    pub(crate) fn rotate(
        &mut self,
        old: ShareKey,
        new: ShareKey,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<ShareKey, SigningError> {
        let op = Signed::try_sign(KeyOp::rotate(old, new), signing_key)?;
        self.ops.insert(op.into());
        Ok(new)
    }

    /// Rotate a [`ShareKey`] in the [`PrekeyState`] with a randomly-generated [`ShareSecretKey`].
    pub(crate) fn rotate_gen<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old: ShareKey,
        signer: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        self.rotate(old, new_secret.share_key(), signer)
    }

    /// Expand the [`PrekeyState`] with a new, randomly-generated [`ShareSecretKey`].
    pub(crate) fn expand<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        let new_secret = ShareSecretKey::generate(csprng);
        let new = new_secret.share_key();
        let op = Signed::try_sign(KeyOp::add(new), signing_key)?;
        self.ops.insert(op.into());
        Ok(new)
    }

    /// Materialize the most recent set of active [`ShareKey`]s in the [`PrekeyState`].
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

#[derive(Debug, Error)]
pub enum NewOpError {
    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error(transparent)]
    MissingDependency(#[from] MissingDependency<ShareKey>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dupe::Dupe;

    #[test]
    fn test_materialization() {
        /*
         * ┌─────────────┐
         * │ share_key_5 │
         * └─────────────┘
         *        │
         *        │
         *        ▼
         * ┌─────────────┐      ┌─────────────┐
         * │ share_key_4 │      │ share_key_3 │
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

        let mut rando = rand::thread_rng();
        let signer = ed25519_dalek::SigningKey::generate(&mut rando);

        let share_key_1 = ShareKey::generate(&mut rando);
        let share_key_2 = ShareKey::generate(&mut rando);
        let share_key_3 = ShareKey::generate(&mut rando);
        let share_key_4 = ShareKey::generate(&mut rando);
        let share_key_5 = ShareKey::generate(&mut rando);

        let op1 = Signed::try_sign(KeyOp::add(share_key_1), &signer).unwrap();
        let op2 = Signed::try_sign(KeyOp::add(share_key_2), &signer).unwrap();

        let op3 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_3), &signer).unwrap();
        let op4 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_4), &signer).unwrap();

        let op5 = Signed::try_sign(KeyOp::rotate(share_key_4, share_key_5), &signer).unwrap();

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

    #[test]
    fn test_causal_delivery() {
        /*
         * ┌─────────────┐
         * │ share_key_5 │
         * └─────────────┘
         *        │
         *        │
         *        ▼
         * ###############      ┌─────────────┐
         * #  (UNKNOWN)  #      │ share_key_3 │
         * ###############      └─────────────┘
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

        let mut rando = rand::thread_rng();
        let signer = ed25519_dalek::SigningKey::generate(&mut rando);

        let share_key_1 = ShareKey::generate(&mut rando);
        let share_key_2 = ShareKey::generate(&mut rando);
        let share_key_3 = ShareKey::generate(&mut rando);
        let share_key_4 = ShareKey::generate(&mut rando);
        let share_key_5 = ShareKey::generate(&mut rando);

        let op1 = Signed::try_sign(KeyOp::add(share_key_1), &signer).unwrap();
        let op2 = Signed::try_sign(KeyOp::add(share_key_2), &signer).unwrap();

        let op3 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_3), &signer).unwrap();
        let op4 = Signed::try_sign(KeyOp::rotate(share_key_1, share_key_4), &signer).unwrap();

        //                                       vvvvvvvvvvv
        let op5 = Signed::try_sign(KeyOp::rotate(share_key_4, share_key_5), &signer).unwrap();

        state.insert_op(op1.dupe()).unwrap();
        state.insert_op(op2.dupe()).unwrap();
        state.insert_op(op3.dupe()).unwrap();
        // Intentionally no inclusion of #4
        assert!(state.insert_op(op5.dupe()).is_err());

        let materialized = state.materialize();
        assert_eq!(materialized.len(), 2);
        assert!(materialized.contains(&share_key_2));
        assert!(materialized.contains(&share_key_3));

        // Same elements again

        state.insert_op(op3).unwrap();
        state.insert_op(op2).unwrap();
        state.insert_op(op1).unwrap();

        let rematerialized = state.materialize();
        assert_eq!(rematerialized.len(), 2);
        assert!(rematerialized.contains(&share_key_2));
        assert!(rematerialized.contains(&share_key_3));

        // Connect op 4 & 5

        state.insert_op(op4).unwrap();
        state.insert_op(op5).unwrap();

        let updated = state.materialize();
        assert_eq!(updated.len(), 3);
        assert!(updated.contains(&share_key_2));
        assert!(updated.contains(&share_key_3));
        assert!(updated.contains(&share_key_5));
    }
}
