use crate::principal::{
    identifier::Identifier, individual::Individual, membered::MemberedId, traits::Verifiable,
};
use crate::{
    access::Access,
    crypto::{
        hash::{CAStore, Hash},
        signed::Signed,
    },
    operation::{delegation::Delegation, revocation::Revocation},
};
use ed25519_dalek::VerifyingKey;
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupState {
    pub id: Identifier,
    pub delegations: CAStore<Signed<Delegation>>,
    pub revocations: CAStore<Signed<Revocation>>,
}

impl From<VerifyingKey> for GroupState {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            delegations: CAStore::new(),
            revocations: CAStore::new(),
        }
    }
}

impl PartialOrd for GroupState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // FIXME use all fields
        match self.id.to_bytes().partial_cmp(&other.id.to_bytes()) {
            Some(Ordering::Equal) => {
                match self.delegations.len().partial_cmp(&other.delegations.len()) {
                    Some(Ordering::Equal) => {
                        self.revocations.len().partial_cmp(&other.revocations.len())
                    }
                    other => other,
                }
            }
            other => other,
        }
    }
}

impl Ord for GroupState {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.id.to_bytes().cmp(&other.id.to_bytes()) {
            Ordering::Equal => match self.delegations.len().cmp(&other.delegations.len()) {
                Ordering::Equal => self.revocations.len().cmp(&other.revocations.len()),
                other => other,
            },
            other => other,
        }
    }
}

impl GroupState {
    pub fn new(parent: Individual) -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifier: VerifyingKey = signing_key.verifying_key();

        let init = Delegation {
            subject: MemberedId::GroupId(verifier.into()),

            from: verifier.into(),
            to: parent.into(),
            can: Access::Admin,

            proof: vec![],
            after_auth: vec![],
        };

        let signed_init: Signed<Delegation> = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id: verifier.into(),
            delegations: CAStore::from_iter([signed_init.into()]),
            revocations: CAStore::new(),
        }
    }

    pub fn add_delegation(
        &mut self,
        delegation: Signed<Delegation>,
    ) -> Result<Hash<Signed<Delegation>>, signature::Error> {
        if delegation.payload.subject != MemberedId::GroupId(self.id.into()) {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        delegation
            .verify()
            .map(|_| self.delegations.insert(delegation))
    }

    pub fn add_revocation(
        &mut self,
        revocation: Signed<Revocation>,
    ) -> Result<Hash<Signed<Revocation>>, signature::Error> {
        if revocation.payload.subject != MemberedId::GroupId(self.id.into()) {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        revocation
            .verify()
            .map(|_| self.revocations.insert(revocation))
    }

    // pub fn get_capability(&self, agent: Agent) -> Option<Capability> {
    //     self.authority_ops.iter().find_map(|op| match op {
    //         Operation::Delegation(delegation) => {
    //             if delegation.to == agent {
    //                 Some(delegation.can)
    //             } else {
    //                 None
    //             }
    //         }
    //         _ => None,
    //     })
    // }
}

impl Verifiable for GroupState {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
