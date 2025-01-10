//! The agents that can delegate to each other.

pub mod active;
pub mod agent;
pub mod document;
pub mod group;
pub mod identifier;
pub mod individual;
pub mod membered;
pub mod public;
pub mod verifiable;

// use super::{
//     cgka::Cgka,
//     content::reference::ContentRef,
//     crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
//     util::content_addressed_map::CaMap,
// };
// use active::Active;
// use agent::id::AgentId;
// use group::{
//     operation::{delegation::Delegation, revocation::Revocation},
//     state::GroupState,
// };
// use identifier::Identifier;
// use individual::state::PrekeyState;
// use membered::Membered;
// use signature::Keypair;
// use std::{
//     cell::RefCell,
//     collections::{HashMap, HashSet},
//     rc::Rc,
// };
//
// // indie
// // group
// // doc
// //
// // indie + group = delegated auth, equivalent to indie <- group
// // indie + doc = (IMPOSSIBLE! Doc implies group!)
// // group + doc = doc
// //
// // indie + group + doc = indie + doc = insecure? no it's okay just weird
//
// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct DocStuff<T: ContentRef> {
//     pub(crate) reader_keys: HashMap<Identifier, (Rc<Entity<T>>, ShareKey)>,
//     pub(crate) content_heads: HashSet<T>,
//     pub(crate) content_state: HashSet<T>,
//     pub(crate) cgka: Cgka,
// }
//
// impl<T: ContentRef> DocStuff<T> {
//     pub fn empty(
//         head: Signed<Delegation<T>>,
//         viewer: Rc<RefCell<Active>>, // FIXME or something
//         delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
//         revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
//     ) -> Result<Self, String> {
//         let mut doc = Self {
//             cgka: Cgka::new(DocumentId(head.subject()), active.borrow().id, viewer_pk)?,
//             reader_keys: Default::default(),
//             content_heads: Default::default(),
//             content_state: Default::default(),
//         };
//         Ok(doc)
//     }
// }
//
// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct Entity<T: ContentRef> {
//     pub(crate) id: Identifier,
//
//     // Individual
//     pub(crate) prekeys: HashSet<ShareKey>,
//     pub(crate) prekey_state: PrekeyState,
//
//     // Group
//     pub(crate) membered: Option<Membered<T>>,
// }
//
// impl<T: ContentRef> Entity<T> {
//     pub(crate) fn empty(id: Identifier) -> Self {
//         Self {
//             id,
//             prekeys: HashSet::new(),
//             prekey_state: PrekeyState::new(),
//             membered: None,
//         }
//     }
//
//     pub fn new_individual<R: rand::CryptoRng + rand::RngCore>(
//         signer: ed25519_dalek::SigningKey,
//         csprng: &mut R,
//     ) -> Self {
//         let mut indie = Self::empty(signer.verifying_key().into());
//         for _ in 0..8 {
//             indie.expand_prekeys(signer, csprng);
//         }
//         indie
//     }
//
//     pub fn new_group<R: rand::CryptoRng + rand::RngCore>(
//         parents: nonempty::NonEmpty<Entity<T>>,
//         csprng: &mut R,
//     ) -> Self {
//         let signer = ed25519_dalek::SigningKey::generate(csprng);
//         let mut group = Self::empty(signer.verifying_key().into());
//         for parent in parents.iter() {
//             group.add_member(todo!("FIXME"));
//         }
//         group
//     }
//
//     #[cfg(feature = "test_utils")]
//     pub fn generate<R: rand::CryptoRng + rand::RngCore>(
//         signer: &ed25519_dalek::SigningKey,
//         csprng: &mut R,
//     ) -> Result<Self, SigningError> {
//         let state = PrekeyState::generate(signer, 8, csprng)?;
//         Ok(Self {
//             id: IndividualId(signer.verifying_key().into()),
//             prekeys: state.materialize(),
//             prekey_state: state,
//         })
//     }
//
//     pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
//         &self.members
//     }
//
//     pub fn receive_delegation(
//         &mut self,
//         delegation: Rc<Signed<Delegation<T>>>,
//     ) -> Result<Digest<Signed<Delegation<T>>>, error::AddError> {
//         let digest = self.state.add_delegation(delegation)?;
//         self.rebuild();
//         Ok(digest)
//     }
//
//     pub fn id(&self) -> Identifier {
//         self.id
//     }
//
//     pub fn receive_prekey_op(&mut self, op: Signed<op::KeyOp>) -> Result<(), ReceivePrekeyOpError> {
//         if op.verifying_key() != self.id.verifying_key() {
//             return Err(ReceivePrekeyOpError::IncorrectSigner);
//         }
//
//         self.prekey_state.insert_op(op)?;
//         self.prekeys = self.prekey_state.materialize();
//         Ok(())
//     }
//
//     pub fn pick_prekey(&self, doc_id: DocumentId) -> ShareKey {
//         let mut bytes: Vec<u8> = self.id.to_bytes().to_vec();
//         bytes.extend_from_slice(&doc_id.to_bytes());
//
//         let prekeys_len = self.prekeys.len();
//         let idx = pseudorandom_in_range(bytes.as_slice(), prekeys_len);
//
//         *self
//             .prekeys
//             .iter()
//             .nth(idx)
//             .expect("index in pre-checked bounds to exist")
//     }
//
//     pub(crate) fn rotate_prekey<R: rand::CryptoRng + rand::RngCore>(
//         &mut self,
//         old_key: ShareKey,
//         signer: ed25519_dalek::SigningKey,
//         csprng: &mut R,
//     ) -> Result<ShareKey, SigningError> {
//         let new_key = self.prekey_state.rotate_gen(old_key, signer, csprng)?;
//         self.prekeys.remove(&old_key);
//         self.prekeys.insert(new_key);
//         Ok(new_key)
//     }
//
//     pub(crate) fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
//         &mut self,
//         signer: ed25519_dalek::SigningKey,
//         csprng: &mut R,
//     ) -> Result<ShareKey, SigningError> {
//         let new_key = self.prekey_state.expand(signer, csprng)?;
//         self.prekeys.insert(new_key);
//         Ok(new_key)
//     }
// }
