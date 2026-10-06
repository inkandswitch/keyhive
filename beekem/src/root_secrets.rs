use crate::{
    collections::Map,
    operation::{CgkaOperation, CgkaOperationGraph},
    pcs_key::PcsKey,
};
use alloc::vec::Vec;
use keyhive_crypto::{digest::Digest, signed::Signed};
use serde::{Deserialize, Serialize};

/// A root secret checked against the update that produced it.
#[derive(Debug)]
pub(crate) struct VerifiedRootSecret {
    op_hash: Digest<Signed<CgkaOperation>>,
    secret: PcsKey,
}

impl VerifiedRootSecret {
    /// Check that `secret` is the root secret the update `op_hash` produced. Its
    /// public key must be the sole share key at the root of that update's path.
    ///
    /// Returns `None` if `graph` has no such key for `op_hash` or `secret` does
    /// not match it.
    pub(crate) fn verify(
        graph: &CgkaOperationGraph,
        op_hash: Digest<Signed<CgkaOperation>>,
        secret: PcsKey,
    ) -> Option<Self> {
        (graph.update_root_share_key(&op_hash)? == secret.0.share_key())
            .then_some(Self { op_hash, secret })
    }
}

/// Root secrets by the update that produced them.
///
/// Entries are added only by [`RootSecrets::insert`], which takes a
/// [`VerifiedRootSecret`], or copied from another [`RootSecrets`] by
/// [`RootSecrets::merge_from`], ensuring every entry was checked against
/// its update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RootSecrets(Map<Digest<Signed<CgkaOperation>>, PcsKey>);

impl RootSecrets {
    /// Record a verified root secret for its update.
    pub(crate) fn insert(&mut self, verified: VerifiedRootSecret) {
        self.0.insert(verified.op_hash, verified.secret);
    }

    /// The root secret recorded for `op_hash`.
    pub(crate) fn get(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Option<PcsKey> {
        self.0.get(op_hash).copied()
    }

    /// Every recorded update with its root secret.
    pub(crate) fn iter(
        &self,
    ) -> impl Iterator<Item = (Digest<Signed<CgkaOperation>>, PcsKey)> + '_ {
        self.0.iter().map(|(op_hash, secret)| (*op_hash, *secret))
    }

    /// Add every secret `other` has recorded, returning the ones not recorded
    /// here before.
    pub(crate) fn merge_from(
        &mut self,
        other: &Self,
    ) -> Vec<(Digest<Signed<CgkaOperation>>, PcsKey)> {
        let mut added = Vec::new();
        for (op_hash, secret) in other.iter() {
            if self.0.insert(op_hash, secret) != Some(secret) {
                added.push((op_hash, secret));
            }
        }
        added
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }

    #[cfg(test)]
    pub(crate) fn remove(&mut self, op_hash: &Digest<Signed<CgkaOperation>>) {
        self.0.remove(op_hash);
    }
}
