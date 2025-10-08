use super::op::{add_key::AddKeyOp, KeyOp};
use crate::{
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{SigningError, VerificationError},
        signer::async_signer::AsyncSigner,
    },
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};

/// Low-level prekey operation store.
///
/// # Semantics
///
/// This is essentially an OR-Set, with a small twist where we avoid the possibility
/// of having a empty set of rebuildd keys by replacing tombstoning with
/// rotation. The number of active prekeys can only expand, but the underlying store
/// is the same size in both cases.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrekeyState {
    /// The actual operations in the [`PrekeyState`].
    ///
    /// This MUST be nonempty. While not enforced at the type level,
    /// the [`new`] constructor ensures that at least one operation is present.
    ops: CaMap<KeyOp>,
}

impl PrekeyState {
    /// Create a new, empty [`PrekeyState`].
    pub fn new(initial_op: KeyOp) -> Self {
        let mut ops = CaMap::new();
        ops.insert(Arc::new(initial_op));
        Self { ops }
    }

    /// Extend a [`PrekeyState`] with elements of an iterator of [`Signed<KeyOp>`]s.
    ///
    /// # Arguments
    ///
    /// * `iter` - An iterator of [`Signed<KeyOp>`]s.
    ///
    /// # Returns
    ///
    /// A new [`PrekeyState`] with the operations from `iter`.
    pub fn extend(
        &mut self,
        iterable: impl IntoIterator<Item = KeyOp>,
    ) -> Result<(), VerificationError> {
        for op in iterable {
            self.insert_op(op)?;
        }
        Ok(())
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
    pub async fn generate<S: AsyncSigner, R: rand::CryptoRng + rand::RngCore>(
        signer: &S,
        size: NonZeroUsize,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let mut futs = FuturesUnordered::new();
        for sk in (0..size.into()).map(|_| ShareSecretKey::generate(csprng)) {
            futs.push(async move {
                signer
                    .try_sign_async(AddKeyOp {
                        share_key: sk.share_key(),
                    })
                    .await
            });
        }

        let mut ops = CaMap::new();
        while let Some(res) = futs.next().await {
            let op = Arc::new(res?);
            ops.insert(Arc::new(KeyOp::from(op)));
        }

        Ok(Self { ops })
    }

    /// A getter for the operations in the [`PrekeyState`].
    pub fn ops(&self) -> &CaMap<KeyOp> {
        &self.ops
    }

    /// A getter for the keys in the [`PrekeyState`].
    pub fn all_keys(&self) -> HashSet<ShareKey> {
        self.ops.values().map(|op| *op.new_key()).collect()
    }

    /// Insert a new [`Signed<KeyOp>`] into the [`PrekeyState`].
    pub fn insert_op(&mut self, op: KeyOp) -> Result<(), VerificationError> {
        op.try_verify()?;
        self.ops.insert(Arc::new(op));
        Ok(())
    }

    /// Check if a [`ShareKey`] is in the [`PrekeyState`].
    pub fn contains_share_key(&self, key: &ShareKey) -> bool {
        self.ops.values().any(|op| op.new_key() == key)
    }

    /// Rebuild the most recent set of active [`ShareKey`]s in the [`PrekeyState`].
    pub fn build(&self) -> HashSet<ShareKey> {
        let mut keys = HashSet::new();
        let mut to_drop = vec![];

        for op in self.ops.values() {
            match op.as_ref() {
                KeyOp::Add(add) => {
                    keys.insert(add.payload.share_key);
                }
                KeyOp::Rotate(rot) => {
                    to_drop.push(rot.payload.old);
                    keys.insert(rot.payload.new);
                }
            }
        }

        for tombstone in to_drop {
            keys.remove(&tombstone);
        }

        keys
    }
}

impl Fork for PrekeyState {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for PrekeyState {
    fn merge(&mut self, fork: Self::Forked) {
        self.ops.merge(fork.ops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::signer::sync_signer::SyncSigner, principal::individual::op::rotate_key::RotateKeyOp,
    };
    use dupe::Dupe;

    #[test]
    fn test_rebuild() {
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

        test_utils::init_logging();

        let mut rando = rand::rngs::OsRng;
        let signer = ed25519_dalek::SigningKey::generate(&mut rando);

        let share_key_1 = ShareKey::generate(&mut rando);
        let share_key_2 = ShareKey::generate(&mut rando);
        let share_key_3 = ShareKey::generate(&mut rando);
        let share_key_4 = ShareKey::generate(&mut rando);
        let share_key_5 = ShareKey::generate(&mut rando);

        let op1: KeyOp = Arc::new(
            signer
                .try_sign_sync(AddKeyOp {
                    share_key: share_key_1,
                })
                .unwrap(),
        )
        .into();

        let mut state = PrekeyState::new(op1.dupe());

        let op2 = Arc::new(
            signer
                .try_sign_sync(AddKeyOp {
                    share_key: share_key_2,
                })
                .unwrap(),
        )
        .into();

        let op3 = Arc::new(
            signer
                .try_sign_sync(RotateKeyOp {
                    old: share_key_1,
                    new: share_key_3,
                })
                .unwrap(),
        )
        .into();

        let op4 = Arc::new(
            signer
                .try_sign_sync(RotateKeyOp {
                    old: share_key_1,
                    new: share_key_4,
                })
                .unwrap(),
        )
        .into();

        let op5 = Arc::new(
            signer
                .try_sign_sync(RotateKeyOp {
                    old: share_key_4,
                    new: share_key_5,
                })
                .unwrap(),
        )
        .into();

        state.insert_op(op1).unwrap();
        state.insert_op(op2).unwrap();
        state.insert_op(op3).unwrap();
        state.insert_op(op4).unwrap();
        state.insert_op(op5).unwrap();

        let built = state.build();
        assert_eq!(built.len(), 3);
        assert!(built.contains(&share_key_2));
        assert!(built.contains(&share_key_3));
        assert!(built.contains(&share_key_5));
    }
}
