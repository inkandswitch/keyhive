use super::document::Document;
use super::individual::Individual;
use super::traits::Verifiable;
use crate::access::Access;
use crate::capability::Capability;
use crate::crypto::encrypted::Encrypted;
use crate::crypto::share_key::ShareKey;
use crate::crypto::signed::Signed;
use crate::crypto::siv::Siv;
use crate::crypto::symmetric_key::SymmetricKey;
use crate::principal::agent::Agent;
use crate::principal::group::operation::delegation::Delegation;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;
use std::fmt::Debug;

#[derive(Clone)]
pub struct Active {
    pub signer: SigningKey,
    pub share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,
}

impl Active {
    pub fn new(signer: SigningKey) -> Self {
        Self {
            signer,
            share_key_pairs: BTreeMap::new(), // FIXME
        }
    }

    pub fn generate() -> Self {
        let signer = SigningKey::generate(&mut rand::thread_rng());
        Self::new(signer)
    }

    pub fn sign<T: Clone>(&self, payload: T) -> Signed<T>
    where
        Vec<u8>: From<T>,
    {
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
            from: self.id(),
            proof: vec![],
            after_auth: vec![], // FIXME
        };

        // FIXME sign delegation
        let delegation: Signed<Delegation> = self.sign(unsigned_delegation);

        cap.subject.add_member(delegation.clone());

        Ok(Capability {
            subject: cap.subject.clone(),
            can: attenuate,

            delegator: Agent::Individual(self.id().into()),
            delegate: to,

            proof: delegation,
        })
    }

    pub fn encrypt_to(
        &self,
        doc: &Document,
        to: &Individual,
        message: &mut [u8],
    ) -> Encrypted<&[u8]> {
        let recipient_share_pk = doc.reader_keys.get(to).expect("FIXME");
        let our_pk = doc.reader_keys.get(&self.id().into()).expect("FIXME");
        let our_sk = self.share_key_pairs.get(our_pk).expect("FIXME");

        let key: SymmetricKey = our_sk
            .diffie_hellman(&recipient_share_pk.clone().into())
            .into();

        let nonce = Siv::new(&key, message, doc);
        let bytes: Vec<u8> = key.encrypt(nonce, message).expect("FIXME").to_vec();

        Encrypted::new(nonce.clone().into(), bytes)
    }
}

pub enum Error {
    Escelation,
}

impl std::fmt::Display for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl Debug for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keypairs_hidden_secret_keys: Vec<(&ShareKey, &str)> = self
            .share_key_pairs
            .iter()
            .map(|(pk, _sk)| (pk, "<SecretKey>"))
            .collect();

        f.debug_struct("Active")
            .field("id", &self.id())
            .field("signer", &"<Signer>")
            .field("share_key_pairs", &keypairs_hidden_secret_keys)
            .finish()
    }
}

impl From<Active> for Agent {
    fn from(active: Active) -> Self {
        Agent::Individual(active.id().into())
    }
}

impl From<Active> for Individual {
    fn from(active: Active) -> Self {
        active.id().into()
    }
}

impl Verifiable for Active {
    fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let active = Active::generate();
        let message = "hello world".as_bytes();
        let signed = active.sign(message);

        assert!(signed.verify().is_ok());
    }
}
