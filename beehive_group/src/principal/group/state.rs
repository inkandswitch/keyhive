use crate::operation::Operation;
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
    pub ops: CAStore<Signed<Operation>>,
}

impl From<VerifyingKey> for GroupState {
    fn from(verifier: VerifyingKey) -> Self {
        GroupState {
            id: verifier.into(),
            ops: CAStore::new(),
        }
    }
}

impl PartialOrd for GroupState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // FIXME use all fields
        match self.id.to_bytes().partial_cmp(&other.id.to_bytes()) {
            Some(Ordering::Equal) => self.ops.len().partial_cmp(&other.ops.len()),
            other => other,
        }
    }
}

impl Ord for GroupState {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.id.to_bytes().cmp(&other.id.to_bytes()) {
            Ordering::Equal => self.ops.len().cmp(&other.ops.len()),
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
        }
        .into();

        let signed_init: Signed<Operation> = Signed::sign(&init, &signing_key);

        // FIXME zeroize signing key

        Self {
            id: verifier.into(),
            ops: CAStore::from_iter([signed_init.into()]),
        }
    }

    pub fn add_op(
        &mut self,
        op: Signed<Operation>,
    ) -> Result<Hash<Signed<Operation>>, signature::Error> {
        if *op.payload.subject() != MemberedId::GroupId(self.id.into()) {
            panic!("FIXME")
            // return Err(signature::Error::InvalidSubject);
        }

        op.verify().map(|_| self.ops.insert(op))
    }

    pub fn get_capability(&self) {
        todo!()
    }
}

impl Verifiable for GroupState {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.id.verifying_key
    }
}
