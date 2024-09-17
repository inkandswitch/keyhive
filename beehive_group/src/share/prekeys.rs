use crate::crypto::share_key::ShareKey;
use crate::principal::stateless::Stateless;
use crate::util::non_empty_set::NonEmptySet;
use ed25519_dalek::VerifyingKey;

// FIXME make sure Signed

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Prekeys {
    pub verifier: Stateless,
    pub sharing_prekeys: NonEmptySet<ShareKey>,
}

impl Prekeys {
    pub fn prekey_for(&self, requestor: VerifyingKey) -> Option<ShareKey> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.verifier.as_slice());
        hasher.update(requestor.as_bytes());
        let hash = hasher.finalize();

        let pre_index = u64::from_be_bytes(hash.as_bytes()[0..8].try_into().expect("FIXME"));
        let index = pre_index % self.sharing_prekeys.len() as u64;

        self.sharing_prekeys.clone().into_iter().nth(index as usize)
    }
}
