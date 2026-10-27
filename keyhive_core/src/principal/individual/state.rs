use super::op::{add_key::AddKeyOp, KeyOp};
use crate::{
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use future_form::FutureForm;
use futures::{prelude::*, stream::FuturesUnordered};
use keyhive_crypto::{
    share_key::{ShareKey, ShareSecretKey},
    signer::async_signer::AsyncSigner,
    verified::{SignError, Verified},
};
use rand::{CryptoRng, RngCore};
use std::{collections::HashSet, num::NonZeroUsize, sync::Arc};

/// Low-level prekey operation store.
///
/// # Semantics
///
/// This is essentially an OR-Set, with a small twist where we avoid the possibility
/// of having a empty set of rebuildd keys by replacing tombstoning with
/// rotation. The number of active prekeys can only expand, but the underlying store
/// is the same size in both cases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Extend a [`PrekeyState`] with verified [`KeyOp`]s.
    pub fn extend(&mut self, iterable: impl IntoIterator<Item = KeyOp>) {
        for op in iterable {
            self.insert_op(op);
        }
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
    /// Returns a [`SignError`] if an operation could not be signed.
    pub async fn generate<F: FutureForm, S: AsyncSigner<F>, R: CryptoRng + RngCore>(
        signer: &S,
        size: NonZeroUsize,
        csprng: &mut R,
    ) -> Result<Self, SignError> {
        let mut futs = FuturesUnordered::new();
        for sk in (0..size.into()).map(|_| ShareSecretKey::generate(csprng)) {
            futs.push(async move {
                Verified::sign::<F, S>(
                    &AddKeyOp {
                        share_key: sk.share_key(),
                    },
                    signer,
                )
                .await
            });
        }

        let mut ops = CaMap::new();
        while let Some(res) = futs.next().await {
            ops.insert(Arc::new(KeyOp::Add(res?)));
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

    /// Insert a verified [`KeyOp`] into the [`PrekeyState`].
    pub fn insert_op(&mut self, op: KeyOp) {
        self.ops.insert(Arc::new(op));
    }

    /// Check if a [`ShareKey`] is in the [`PrekeyState`].
    pub fn contains_share_key(&self, key: &ShareKey) -> bool {
        self.ops.values().any(|op| op.new_key() == key)
    }

    /// Rebuild the most recent set of active [`ShareKey`]s in the [`PrekeyState`].
    pub fn build(&self) -> HashSet<ShareKey> {
        let mut keys = HashSet::with_capacity(self.ops.len());
        let mut to_drop = Vec::with_capacity(self.ops.len());

        for op in self.ops.values() {
            match op.as_ref() {
                KeyOp::Add(add) => {
                    keys.insert(add.payload().share_key);
                }
                KeyOp::Rotate(rot) => {
                    to_drop.push(rot.payload().old);
                    keys.insert(rot.payload().new);
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
    use crate::principal::individual::op::rotate_key::RotateKeyOp;
    use dupe::Dupe;
    use keyhive_crypto::signer::memory::MemorySigner;
    use rand::rngs::OsRng;

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

        let mut rando = OsRng;
        let signer = MemorySigner::generate(&mut rando);

        let share_key_1 = ShareKey::generate(&mut rando);
        let share_key_2 = ShareKey::generate(&mut rando);
        let share_key_3 = ShareKey::generate(&mut rando);
        let share_key_4 = ShareKey::generate(&mut rando);
        let share_key_5 = ShareKey::generate(&mut rando);

        let op1 = KeyOp::Add(
            Verified::sign_sync(
                &AddKeyOp {
                    share_key: share_key_1,
                },
                &signer,
            )
            .unwrap(),
        );

        let mut state = PrekeyState::new(op1.dupe());

        let op2 = KeyOp::Add(
            Verified::sign_sync(
                &AddKeyOp {
                    share_key: share_key_2,
                },
                &signer,
            )
            .unwrap(),
        );

        let op3 = KeyOp::Rotate(
            Verified::sign_sync(
                &RotateKeyOp {
                    old: share_key_1,
                    new: share_key_3,
                },
                &signer,
            )
            .unwrap(),
        );

        let op4 = KeyOp::Rotate(
            Verified::sign_sync(
                &RotateKeyOp {
                    old: share_key_1,
                    new: share_key_4,
                },
                &signer,
            )
            .unwrap(),
        );

        let op5 = KeyOp::Rotate(
            Verified::sign_sync(
                &RotateKeyOp {
                    old: share_key_4,
                    new: share_key_5,
                },
                &signer,
            )
            .unwrap(),
        );

        state.insert_op(op1);
        state.insert_op(op2);
        state.insert_op(op3);
        state.insert_op(op4);
        state.insert_op(op5);

        let built = state.build();
        assert_eq!(built.len(), 3);
        assert!(built.contains(&share_key_2));
        assert!(built.contains(&share_key_3));
        assert!(built.contains(&share_key_5));
    }
}
