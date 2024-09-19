use super::identifier::Identifier;
use super::individual::Individual;
use super::traits::Verifiable;
use crate::access::Access;
use crate::capability::Capability;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::operation::delegation::Delegation;
use crate::principal::agent::Agent;
use crate::principal::group::state::GroupState;
use crate::principal::membered::MemberedId;
use crate::util::hidden::Hidden;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Debug;

#[derive(Clone)]
pub struct Active {
    id: Identifier,
    signer: SigningKey,
    share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,
}

impl Active {
    pub fn new(id: Identifier, signer: SigningKey) -> Self {
        Self {
            id,
            signer,
            share_key_pairs: BTreeMap::new(),
        }
    }

    pub fn sign<T: Clone + Into<Vec<u8>>>(&self, payload: &T) -> Signed<T> {
        Signed::<T>::sign(payload, &self.signer)
    }

    // FIXME put this on Capability?
    pub fn delegate_group(
        &self,
        cap: &mut Capability,
        attenuate: Access,
        to: Agent,
    ) -> Result<Capability, Error> {
        if attenuate > cap.can {
            return Err(Error::Escelation);
        }

        let unsigned_delegation = Delegation {
            subject: cap.subject.member_id(),
            can: attenuate,
            to: to.clone(),
            from: self.id,
            proof: vec![],
            after_auth: vec![], // FIXME
        };

        // FIXME sign delegation
        let delegation: Signed<Delegation> = self.sign(&unsigned_delegation);

        cap.subject.add_member(delegation.clone());

        Ok(Capability {
            subject: cap.subject.clone(),
            can: attenuate,

            delegator: Agent::Individual(self.id.into()),
            delegate: to,

            proof: delegation,
        })
    }
}

pub enum Error {
    Escelation,
}

impl Debug for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keypairs_hidden_secret_keys: Vec<(&ShareKey, Hidden)> = self
            .share_key_pairs
            .iter()
            .map(|(pk, _sk)| (pk, Hidden))
            .collect();

        f.debug_struct("Active")
            .field("id", &self.id)
            .field("signer", &Hidden)
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
        self.id.verifying_key
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}
