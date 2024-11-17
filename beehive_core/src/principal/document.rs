pub mod encryption;
pub mod id;
pub mod store;

use super::{individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    cgka::{encryption_key::ApplicationSecretMetadata, Cgka},
    content::reference::ContentRef,
    crypto::{
        encrypted::Encrypted,
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
    },
    principal::{
        agent::{Agent, AgentId},
        group::{
            operation::{
                delegation::{Delegation, DelegationError},
                AncestorError,
            },
            Group,
        },
        identifier::Identifier,
        individual::Individual,
    },
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use id::DocumentId;
use nonempty::NonEmpty;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document<T: ContentRef> {
    pub(crate) group: Group<T>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<Individual>, ShareKey)>,

    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    // FIXME: This doesn't work right now because Cgka is not Eq or PartialEq
    pub(crate) cgka: Cgka<T>,
}

impl<T: ContentRef> Document<T> {
    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T>>> {
        self.group.delegations()
    }

    pub fn get_capabilty(&self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<T>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate(parents: NonEmpty<Agent<T>>) -> Result<Self, DelegationError> {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let group =
            parents
                .iter()
                .try_fold(Group::generate(parents.clone())?, |mut acc, parent| {
                    let dlg = Signed::try_sign(
                        Delegation {
                            delegate: parent.dupe(),
                            can: Access::Admin,
                            proof: None,
                            after_revocations: vec![],
                            after_content: BTreeMap::new(),
                        },
                        &doc_signer,
                    )?;

                    let rc = Rc::new(dlg);
                    acc.state.delegations.insert(rc.dupe());
                    acc.state.delegation_heads.insert(rc.dupe());
                    acc.members.insert(parent.agent_id(), vec![rc]);

                    Ok::<Group<T>, DelegationError>(acc)
                })?;

        let owner_id = IndividualId(Identifier((&doc_signer).into()));
        let initial_share_secret_key = ShareSecretKey::generate();
        let initial_share_key = initial_share_secret_key.share_key();
        let doc_id = DocumentId(group.id());
        // FIXME: Get the initial tree members and a pre-key for each. Right now there's
        // no path to this list. The Group only has AgentIds, but we need to get the
        // recursive membership list (e.g. to get all IndividualIds in an AgentId
        // corresponding to another Group).
        let members = vec![(owner_id, initial_share_key)];
        let cgka = Cgka::new(
            members,
            doc_id,
            owner_id,
            initial_share_key,
            initial_share_secret_key,
        )
        .expect("FIXME");

        Ok(Document {
            group,
            reader_keys: Default::default(), // FIXME
            content_state: Default::default(),
            content_heads: Default::default(),
            cgka,
        })
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);

        match self.group.members.get_mut(&id) {
            Some(caps) => {
                caps.push(rc);
            }
            None => {
                self.group.members.insert(id, vec![rc]);
            }
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<Document<T>>],
    ) -> Result<(), SigningError> {
        self.group
            .revoke_member(member_id, signing_key, relevant_docs)
    }

    pub fn materialize(&mut self) -> Result<(), AncestorError> {
        self.group.materialize()
    }

    pub fn has_pcs_key(&self) -> bool {
        self.cgka.has_pcs_key()
    }

    // FIXME: Add error type
    pub fn pcs_update(&mut self, id: IndividualId, pk: ShareKey, sk: ShareSecretKey) {
        self.cgka.update(id, pk, sk).expect("FIXME");
    }

    pub fn encrypt_content(
        &mut self,
        content_ref: &T,
        content: &[u8],
        // FIXME: What should this type really be?
        pred_ref: &T,
        // FIXME: We should only need to pass in a public and secret key when
        // doing a PCS update. Note that if the BeeKEM tree does not contain a
        // root secret (e.g. because of conflict keys), then you need to do an
        // PCS update before you can encrypt.
        // One approach would be to assume encrypt_content will only be called
        // after checking if there is a current root secret. That's what we're doing
        // right now.
    ) -> Encrypted<Vec<u8>> {
        let app_secret = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_ref)
            .expect("FIXME");
        let mut ciphertext = content.to_vec();
        app_secret
            .key()
            .try_encrypt(app_secret.metadata().nonce, &mut ciphertext)
            .unwrap();
        Encrypted::new(app_secret.metadata().nonce, ciphertext)
    }

    pub fn decrypt_content(
        &mut self,
        encrypted_content: &Encrypted<Vec<u8>>,
        metadata: &ApplicationSecretMetadata<T>,
    ) -> Vec<u8> {
        let decrypt_key = self
            .cgka
            .decryption_key_for(&metadata)
            .expect("FIXME")
            .expect("FIXME");
        let mut plaintext = encrypted_content.ciphertext.clone();
        decrypt_key
            .try_decrypt(encrypted_content.nonce, &mut plaintext)
            .expect("FIXME");
        plaintext
    }
}

// FIXME test
impl<T: ContentRef> std::hash::Hash for Document<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group.hash(state);

        for key in self.reader_keys.keys() {
            key.hash(state);
        }

        for c in self.content_state.iter() {
            c.hash(state);
        }
    }
}

impl<T: ContentRef> Verifiable for Document<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
