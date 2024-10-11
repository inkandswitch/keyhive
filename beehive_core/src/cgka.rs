// Where should we handle the message details for propagating changes (updates and removes)
// to other nodes over the network?

pub trait CGKA<PK, SK> {
    /// Rotate key.
    fn update(old_pk: PK, new_pk: PK, new_sk: SK);
    /// Remove key.
    fn remove(pk: PK);
}

use serde::{Deserialize, Serialize};
use x25519_dalek;

use crate::crypto::encrypted::Encrypted;
type PublicKey = x25519_dalek::PublicKey;
type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub struct CausalTreeKEM {
    root: CTKNode,
}

impl CausalTreeKEM {
    pub fn new(pks: Vec<PublicKey>) -> Self {
        todo!()
        // FIXME: Build left-balanced binary tree with pks as leaves.
    }
}

// TODO: Can we assume causal broadcast?
impl CGKA<PublicKey, SecretKey> for CausalTreeKEM {
    /// Rotate key.
    fn update(old_pk: PublicKey, new_pk: PublicKey, new_sk: SecretKey) {
        todo!()
    }

    /// Remove key.
    fn remove(pk: PublicKey) {
        todo!()
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct CTKNode {
    /// Present unless blanked
    pub pk: Option<PublicKey>,
    /// Only present at intermediate nodes and root, not the leaves.
    pub sk: Option<Encrypted<SecretKey>>,
    pub left: Option<Box<CTKNode>>,
    pub right: Option<Box<CTKNode>>,
}

impl CTKNode {
    // FIXME
    pub fn new(pk: PublicKey, sk: Option<Encrypted<SecretKey>>) -> Self {
        Self {
            pk: Some(pk),
            sk,
            left: None,
            right: None,
        }
    }

    /// Highest non-blank descendents of a node
    fn resolution(&self) -> Vec<&Box<CTKNode>> {
        if let Some(pk) = self.pk {
            // Return just this node
            todo!()
        } else {
            match (&self.left, &self.right) {
                (Some(l), Some(r)) => {
                    let mut l_res = l.resolution();
                    l_res.extend(r.resolution());
                    l_res
                }
                (Some(l), None) => l.resolution(),
                (None, Some(r)) => r.resolution(),
                _ => Vec::new(),
            }
        }
    }
}

// Derive key pair
fn dkp(x: &[u8]) -> (PublicKey, SecretKey) {
    todo!()
}

// Key derivation function
// Second input is used to prevent collisions (e.g. "path" or "node")
// fn kdf(&[u8], &[u8]) -> ???

/// Requires the following properties:
///   1: If (x, X) and (y, Y) are valid key pairs, then so is (x, X) * (y, Y) = (x *pub y, X *priv Y).
///   2: * is associative and commutative (ensuring order of concurrent updates doesn't matter).
///   3: *pub is cancellative: if x *pub z = y *pub z for some z, then x = y.
fn star(pk: PublicKey, sk: SecretKey) -> (PublicKey, SecretKey) {
    (star_pub(pk), star_priv(sk))
}

fn star_pub(pk: PublicKey) -> PublicKey {
    todo!()
}

fn star_priv(sk: SecretKey) -> SecretKey {
    todo!()
}
