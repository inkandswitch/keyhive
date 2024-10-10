use serde::{Deserialize, Serialize};
use x25519_dalek;

use crate::{crypto::encrypted::Encrypted, principal::identifier::Identifier};
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
impl CausalTreeKEM {
    /// Add key.
    fn add(pk: PublicKey) {
        todo!()
    }

    /// Contains key.
    fn contains(pk: PublicKey) {
        todo!()
    }

    /// Remove key.
    fn remove(pk: PublicKey) {
        todo!()
    }

    /// Rotate key.
    fn update(old_pk: PublicKey, new_pk: PublicKey, new_sk: SecretKey) {
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



// pub enum CTKNode {
//     Blank {
//         left: Option<Box<CTKNode>>,
//         right: Option<Box<CTKNode>>,
//         leaf_count: usize,
//     },
//     Node {
//         pk: PublicKey,
//         sk: Encrypted<SecretKey>,
//         parent: Option<Box<CTKNode>>,
//         left: Option<Box<CTKNode>>,
//         right: Option<Box<CTKNode>>,
//         leaf_count: usize,
//     },
//     Leaf {
//         parent: Option<Box<CTKNode>>,
//         id: Identifier,
//         pk: PublicKey,
//     },
// }

// impl CTKNode {
//     // FIXME
//     pub fn new(pk: PublicKey, sk: Option<Encrypted<SecretKey>>) -> Self {
//         Self {
//             pk: Some(pk),
//             sk,
//             left: None,
//             right: None,
//         }
//     }

//     /// Highest non-blank descendents of a node
//     fn resolution(&self) -> Vec<&Box<CTKNode>> {
//         let left_resolution = resolve_node(&self.left);
//         let right_resolution = resolve_node(&self.right);
//         left_resolution.extend(right_resolution);
//         left_resolution
//     }
// }

// fn resolve_node(maybe_node: &Option<Box<CTKNode>>) -> Vec<&Box<CTKNode>> {
//     let Some(node) = maybe_node else {
//         return Vec::new()
//     };
//     match node {
//         Blank { .. } => node.resolution(),
//         _ => vec![node]
//     }
// }
