use super::traits::Verifiable;
use crate::crypto::share_key::ShareKey;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use std::fmt::Debug;

// FIXME also add sharing preivate keys

#[derive(Clone)]
pub struct Active {
    verifier: VerifyingKey,
    signer: SigningKey,
    share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hidden;

impl Debug for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keypairs_hidden_secret_keys: Vec<(&ShareKey, Hidden)> = self
            .share_key_pairs
            .iter()
            .map(|(pk, _sk)| (pk, Hidden))
            .collect();

        f.debug_struct("Active")
            .field("verifier", &self.verifier)
            .field("signer", &"SigningKey")
            .field("share_key_pairs", &keypairs_hidden_secret_keys)
            .finish()
    }
}

// impl PartialOrd for Active {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.verifier
//             .to_bytes()
//             .partial_cmp(&other.verifier.to_bytes())
//     }
// }
//
// impl Ord for Active {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.verifier.to_bytes().cmp(&other.verifier.to_bytes())
//     }
// }

impl Verifiable for Active {
    fn verifying_key(&self) -> VerifyingKey {
        self.verifier
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}
