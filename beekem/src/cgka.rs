//! Exposes CGKA (Continuous Group Key Agreement) operations like deriving
//! a new application secret, rotating keys, and adding and removing members
//! from the group.
//!
//! A CGKA protocol is responsible for maintaining a stream of shared group keys
//! updated over time. We are using a variant of the TreeKEM protocol (which
//! we call BeeKEM) adapted for local-first contexts.
//!
//! We assume that all operations are received in causal order (a property
//! guaranteed by Keyhive as a whole).

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    encrypted::{encrypt_secret, EncryptedContent},
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{NodeKey, ShareKeyMap},
    operation::{Bridge, CgkaEpoch, CgkaOperation, CgkaOperationGraph, Invitation},
    pcs_key::{ApplicationSecret, PcsKey},
    transact::{Fork, Merge},
    tree::BeeKem,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::hash::{Hash, Hasher};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::async_signer::{self, AsyncSigner},
    siv::Siv,
    symmetric_key::SymmetricKey,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

/// Exposes CGKA (Continuous Group Key Agreement) operations like deriving
/// a new application secret, rotating keys, and adding and removing members
/// from the group.
///
/// A CGKA protocol is responsible for maintaining a stream of shared group keys
/// updated over time. We are using a variant of the TreeKEM protocol (which
/// we call BeeKEM) adapted for local-first contexts.
///
/// We assume that all operations are received in causal order (a property
/// guaranteed by Keyhive as a whole).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cgka {
    doc_id: TreeId,
    /// The id of the member who owns this tree.
    pub owner_id: MemberId,
    /// The secret keys of the member who owns this tree.
    pub owner_sks: ShareKeyMap,
    tree: BeeKem,
    /// Graph of all operations seen (but not necessarily applied) so far.
    ops_graph: CgkaOperationGraph,
    /// Whether there are ops in the graph that have not been applied to the
    /// tree due to a structural change.
    pending_ops_for_structural_change: bool,
    // TODO: Enable policies to evict older entries.
    pcs_keys: CaMap<PcsKey>,

    /// The update operations for each PCS key.
    pcs_key_ops: Map<Digest<PcsKey>, Digest<Signed<CgkaOperation>>>,

    /// The most recent PCS key we know encrypted a piece of content.
    newest_encrypting_pcs_key: Option<Digest<PcsKey>>,

    /// Invitations for new members.
    invitations: Map<MemberId, Vec<Invitation>>,

    /// Bridges. Map keys are the root secret each wraps.
    bridges: Map<Digest<PcsKey>, Vec<Bridge>>,

    /// The root secrets that it was last reported content heads were
    /// encrypted under.
    reported_head_secrets: Vec<Digest<PcsKey>>,

    original_member: (MemberId, ShareKey),
    init_add_op: Signed<CgkaOperation>,
}

impl Hash for Cgka {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.doc_id.hash(state);
        self.owner_id.hash(state);
        self.owner_sks.hash(state);
        self.tree.hash(state);
        self.ops_graph.hash(state);
        self.pending_ops_for_structural_change.hash(state);
        self.pcs_keys.keys().collect::<BTreeSet<_>>().hash(state);
        self.pcs_key_ops
            .keys()
            .map(|k| k.as_slice())
            .collect::<BTreeSet<_>>()
            .hash(state);
        self.newest_encrypting_pcs_key.hash(state);
        self.invitations
            .iter()
            .collect::<BTreeMap<_, _>>()
            .hash(state);
        self.bridges.iter().collect::<BTreeMap<_, _>>().hash(state);
        self.reported_head_secrets.hash(state);
        self.original_member.hash(state);
        self.init_add_op.hash(state);
    }
}

impl Cgka {
    pub async fn new<F: FutureForm, S: AsyncSigner<F>>(
        doc_id: TreeId,
        owner_id: MemberId,
        owner_pk: ShareKey,
        signer: &S,
    ) -> Result<Self, CgkaError> {
        let init_add_op = CgkaOperation::init_add(doc_id, owner_id, owner_pk);
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, init_add_op).await?;
        Self::new_from_init_add(doc_id, owner_id, owner_pk, signed_op)
    }

    #[instrument(skip_all)]
    pub fn new_from_init_add(
        doc_id: TreeId,
        owner_id: MemberId,
        owner_pk: ShareKey,
        init_add_op: Signed<CgkaOperation>,
    ) -> Result<Self, CgkaError> {
        let tree = BeeKem::new(doc_id, owner_id, owner_pk)?;
        let mut cgka = Self {
            doc_id,
            owner_id,
            owner_sks: ShareKeyMap::new(),
            tree,
            ops_graph: CgkaOperationGraph::new(),
            pending_ops_for_structural_change: false,
            pcs_keys: CaMap::new(),
            pcs_key_ops: Map::new(),
            newest_encrypting_pcs_key: None,
            invitations: Map::new(),
            bridges: Map::new(),
            reported_head_secrets: Vec::new(),
            original_member: (owner_id, owner_pk),
            init_add_op: init_add_op.clone(),
        };
        cgka.ops_graph.add_local_op(&init_add_op);
        Ok(cgka)
    }

    #[instrument(skip_all)]
    pub fn with_new_owner(
        &self,
        my_id: MemberId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        let mut cgka = self.clone();
        cgka.owner_id = my_id;
        cgka.owner_sks = owner_sks;
        cgka.pcs_keys = self.pcs_keys.clone();
        cgka.pcs_key_ops = self.pcs_key_ops.clone();
        Ok(cgka)
    }

    pub fn init_add_op(&self) -> Signed<CgkaOperation> {
        self.init_add_op.clone()
    }

    /// Get the count of CGKA operations in the graph.
    pub fn ops_count(&self) -> usize {
        self.ops_graph.cgka_ops.len()
    }

    /// Derive an [`ApplicationSecret`] from our current [`PcsKey`] for new content
    /// to encrypt.
    ///
    /// If the tree does not currently contain a root key, then we must first
    /// perform a leaf key rotation.
    #[instrument(skip_all)]
    #[allow(clippy::type_complexity)]
    pub async fn new_app_secret_for<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        R: rand::CryptoRng + rand::RngCore,
    >(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(ApplicationSecret<T>, Option<Signed<CgkaOperation>>), CgkaError> {
        let mut op = None;
        let current_pcs_key = if !self.has_pcs_key() {
            let new_share_secret_key = ShareSecretKey::generate(csprng);
            let new_share_key = new_share_secret_key.share_key();
            let (pcs_key, update_op) = self
                .update::<F, S, R>(new_share_key, new_share_secret_key, signer, csprng)
                .await?;
            self.record_encrypting_pcs_key(&pcs_key, Digest::hash(&update_op));
            op = Some(update_op);
            pcs_key
        } else {
            let pcs_key = self.pcs_key_from_tree_root()?;
            let pcs_hash = Digest::hash(&pcs_key);
            // `has_pcs_key()` above guarantees a single head.
            debug_assert!(self.ops_graph.has_single_head());
            let op_hash = self
                .pcs_key_ops
                .get(&pcs_hash)
                .copied()
                .or_else(|| self.ops_graph.cgka_op_heads.iter().next().copied());
            if let Some(op_hash) = op_hash {
                self.record_encrypting_pcs_key(&pcs_key, op_hash);
            }
            pcs_key
        };
        let pcs_key_hash = Digest::hash(&current_pcs_key);
        let nonce = Siv::new(&current_pcs_key.into(), content, self.doc_id.as_bytes());
        Ok((
            current_pcs_key.derive_application_secret(
                &nonce,
                content_ref,
                &Digest::hash(pred_refs),
                self.pcs_key_ops
                    .get(&pcs_key_hash)
                    .expect("PcsKey hash should be present because we derived it above"),
            ),
            op,
        ))
    }

    /// Derive a decryption key for encrypted data.
    ///
    /// We must first derive a [`PcsKey`] for the encrypted data's associated
    /// hashes. Then we use that [`PcsKey`] to derive an [`ApplicationSecret`].
    #[instrument(skip_all)]
    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &EncryptedContent<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        let pcs_key =
            self.pcs_key_from_hashes(&encrypted.pcs_key_hash, &encrypted.pcs_update_op_hash)?;
        // We can only decrypt with a key that was at some point used to encrypt.
        self.record_encrypting_pcs_key(&pcs_key, encrypted.pcs_update_op_hash);
        let app_secret = pcs_key.derive_application_secret(
            &encrypted.nonce,
            &encrypted.content_ref,
            &encrypted.pred_refs,
            &encrypted.pcs_update_op_hash,
        );
        Ok(app_secret.key())
    }

    pub fn has_pcs_key(&self) -> bool {
        self.tree.has_root_key()
            && self.ops_graph.has_single_head()
            && self.ops_graph.add_heads.len() < 2
    }

    /// Add member to group.
    ///
    /// Returns the add operation and an [`CgkaOperation::Invite`] (if we have
    /// access to a root secret used to encrypt content). Empty if the member is
    /// already in the tree.
    #[instrument(skip_all)]
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        pk: ShareKey,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        if self.tree.contains_id(&id) {
            return Ok(Vec::new());
        }
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        let invitation = self.invitation_for(id, pk);
        let leaf_index = self.tree.push_leaf(id, pk.into());
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let add_predecessors = Vec::from_iter(self.ops_graph.add_heads.iter().cloned());
        let op = CgkaOperation::Add {
            added_id: id,
            pk,
            leaf_index,
            predecessors,
            add_predecessors,
            doc_id: self.doc_id,
        };

        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.ops_graph.add_local_op(&signed_op);
        let mut ops = alloc::vec![signed_op];

        if let Some(invitation) = invitation {
            let op = CgkaOperation::Invite {
                invitation: alloc::boxed::Box::new(invitation),
                predecessors: Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned()),
                doc_id: self.doc_id,
            };
            let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
            self.record_invitation(&signed_op);
            self.ops_graph.add_local_op(&signed_op);
            ops.push(signed_op);
        } else {
            info!(
                "no root secret to invite {:?} with; it can only read content written from now on",
                id
            );
        }
        Ok(ops)
    }

    /// Add multiple members to group.
    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(MemberId, ShareKey)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut ops = Vec::new();
        for m in members {
            ops.extend(self.add::<F, S>(m.0, m.1, signer).await?);
        }
        Ok(ops)
    }

    /// Build an invitation for a member we are adding.
    ///
    /// Returns `None` if we don't have access to any root secret that was used
    /// to encrypt content.
    #[instrument(skip_all)]
    fn invitation_for(&self, invitee_id: MemberId, invitee_pk: ShareKey) -> Option<Invitation> {
        let (root_secret, pcs_key_hash, pcs_update_op_hash) =
            self.newest_known_encrypting_pcs_key()?;
        let (inviter_pk, inviter_sk) = self.inviter_key_pair()?;
        let encrypted = encrypt_secret(
            self.doc_id.as_bytes(),
            root_secret.0,
            &inviter_sk,
            &invitee_pk,
        )
        .ok()?;
        Some(Invitation {
            invitee_id,
            invitee_pk,
            root_secret: encrypted,
            inviter_pk,
            pcs_key_hash,
            pcs_update_op_hash,
        })
    }

    /// The newest root secret we know content is encrypted under, along with
    /// the two hashes sent with that encrypted content. Returns `None` if we
    /// don't know of any.
    fn newest_known_encrypting_pcs_key(
        &self,
    ) -> Option<(PcsKey, Digest<PcsKey>, Digest<Signed<CgkaOperation>>)> {
        if let Some(hash) = self.newest_encrypting_pcs_key {
            if let (Some(key), Some(op)) = (self.pcs_keys.get(&hash), self.pcs_key_ops.get(&hash)) {
                return Some((**key, hash, *op));
            }
        }
        self.encrypting_pcs_key_from_our_invitation()
    }

    /// The root secret from an invitation addressed to us.
    ///
    /// If we are inviting another member in turn and do not yet have access
    /// in the tree to a secret used for encryption, we can encrypt this secret for
    /// the invitation instead.
    fn encrypting_pcs_key_from_our_invitation(
        &self,
    ) -> Option<(PcsKey, Digest<PcsKey>, Digest<Signed<CgkaOperation>>)> {
        [self.owner_id, MemberId::public()]
            .into_iter()
            .filter_map(|id| self.invitations.get(&id))
            .flatten()
            .find_map(|invitation| {
                let key = self.pcs_key_from_invitation(&invitation.pcs_key_hash)?;
                Some((key, invitation.pcs_key_hash, invitation.pcs_update_op_hash))
            })
    }

    /// A key pair at our own leaf, for the Diffie-Hellman exchange that
    /// encrypts an invitation.
    ///
    /// Falls back to Public's leaf when we are not in the tree ourselves, the
    /// same way [`Self::update`] does. Returns `None` if neither has access.
    fn inviter_key_pair(&self) -> Option<(ShareKey, ShareSecretKey)> {
        let id = if self.tree.contains_id(&self.owner_id) {
            self.owner_id
        } else {
            MemberId::public()
        };
        self.tree
            .node_key_for_id(id)
            .ok()?
            .keys()
            .into_iter()
            .find_map(|pk| self.owner_sks.get(&pk).map(|sk| (pk, *sk)))
    }

    /// Checks if there are content heads that a member cannot currently decrypt
    /// (for example, a fork whose other branch used a secret they cannot derive).
    /// If so, returns bridge ops to allow them to decrypt.
    ///
    /// `head_key_hashes` are the secrets those heads were encrypted under.
    /// It normally returns an empty `Vec`.
    ///
    /// Call this when the set of content heads changes.
    #[instrument(skip_all)]
    pub async fn bridge_content_heads<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        head_key_hashes: &[Digest<PcsKey>],
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let mut seen = Set::new();
        self.reported_head_secrets = head_key_hashes
            .iter()
            .filter(|hash| seen.insert(**hash))
            .copied()
            .collect();
        self.bridge_reported_heads::<F, S>(signer).await
    }

    /// Re-examine the heads a caller last reported.
    #[instrument(skip_all)]
    pub async fn bridge_reported_heads<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let heads = self.reported_head_secrets.clone();
        // If there is only one secret, it can be used to decrypt every head
        // here and there is no need for a bridge. This is the common case.
        if heads.len() < 2 {
            return Ok(Vec::new());
        }

        let members: Vec<MemberId> = self.tree.member_ids().collect();
        let add_ops = self.add_ops_by_member();
        let reaching: Vec<(Digest<PcsKey>, Set<MemberId>)> = heads
            .iter()
            .map(|hash| (*hash, self.members_reaching(hash, &members, &add_ops)))
            .collect();

        let mut wanted: Vec<(Digest<PcsKey>, Digest<PcsKey>)> = Vec::new();
        for (closed, reached) in &reaching {
            let mut blocked: Set<MemberId> = members
                .iter()
                .filter(|member| !reached.contains(member))
                .copied()
                .collect();
            for under in self.bridge_encryption_key_candidates(&heads, closed, &blocked) {
                if blocked.is_empty() {
                    break;
                }
                let covered = self.members_reaching(&under, &members, &add_ops);
                if !blocked.iter().any(|member| covered.contains(member)) {
                    continue;
                }
                blocked.retain(|member| !covered.contains(member));
                wanted.push((*closed, under));
            }
        }

        let mut ops = Vec::new();
        for (pcs_key_hash, under) in wanted {
            if let Some(op) = self.bridge::<F, S>(pcs_key_hash, under, signer).await? {
                ops.push(op);
            }
        }
        Ok(ops)
    }

    /// The members that can reach `pcs_key_hash`.
    ///
    /// Either they were in the tree when it was created or they received it
    /// in an invitation.
    fn members_reaching(
        &self,
        pcs_key_hash: &Digest<PcsKey>,
        members: &[MemberId],
        add_ops: &Map<MemberId, Vec<Digest<Signed<CgkaOperation>>>>,
    ) -> Set<MemberId> {
        let ancestors = self
            .pcs_key_ops
            .get(pcs_key_hash)
            .map(|update_op| self.ops_graph.ancestors_of(update_op))
            .unwrap_or_default();
        members
            .iter()
            .filter(|member| {
                self.invitations.get(member).is_some_and(|invitations| {
                    invitations
                        .iter()
                        .any(|invitation| invitation.pcs_key_hash == *pcs_key_hash)
                }) || add_ops
                    .get(member)
                    .is_some_and(|adds| adds.iter().any(|add| ancestors.contains(add)))
            })
            .copied()
            .collect()
    }

    /// The operations that added each member.
    ///
    /// A member removed and added again has more than one.
    fn add_ops_by_member(&self) -> Map<MemberId, Vec<Digest<Signed<CgkaOperation>>>> {
        let mut acc: Map<MemberId, Vec<Digest<Signed<CgkaOperation>>>> = Map::new();
        for (hash, op) in self.ops_graph.cgka_ops.iter() {
            if let CgkaOperation::Add { added_id, .. } = op.payload {
                acc.entry(added_id).or_default().push(*hash);
            }
        }
        acc
    }

    /// PCS keys we could potentially use to encrypt `closed` for a bridge.
    fn bridge_encryption_key_candidates(
        &self,
        heads: &[Digest<PcsKey>],
        closed: &Digest<PcsKey>,
        blocked: &Set<MemberId>,
    ) -> Vec<Digest<PcsKey>> {
        let mut seen = Set::new();
        heads
            .iter()
            .copied()
            .chain(
                blocked
                    .iter()
                    .filter_map(|member| self.invitations.get(member))
                    .flatten()
                    .map(|invitation| invitation.pcs_key_hash),
            )
            .filter(|hash| hash != closed && seen.insert(*hash) && self.pcs_keys.contains_key(hash))
            .collect()
    }

    /// Create a bridge from `under` to `pcs_key_hash` for members that can derive
    /// the former but not the latter.
    ///
    /// Returns `None` when we are missing either secret, `pcs_key_hash` and `under`
    /// are equivalent, or a bridge between them is already present.
    #[instrument(skip_all)]
    async fn bridge<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        pcs_key_hash: Digest<PcsKey>,
        under: Digest<PcsKey>,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if pcs_key_hash == under || self.has_bridge(&pcs_key_hash, &under) {
            return Ok(None);
        }
        let (Some(secret), Some(under_key)) = (
            self.pcs_keys.get(&pcs_key_hash).map(|key| **key),
            self.pcs_keys.get(&under).map(|key| **key),
        ) else {
            return Ok(None);
        };
        let (Some(pcs_update_op_hash), Some(under_update_op_hash)) = (
            self.pcs_key_ops.get(&pcs_key_hash).copied(),
            self.pcs_key_ops.get(&under).copied(),
        ) else {
            return Ok(None);
        };

        let root_secret = under_key
            .derive_bridge_key()
            .try_seal(secret.0.as_slice(), self.doc_id.as_bytes())
            .map_err(CgkaError::Encryption)?;
        let op = CgkaOperation::Bridge {
            bridge: alloc::boxed::Box::new(Bridge {
                root_secret,
                pcs_key_hash,
                pcs_update_op_hash,
                under,
                under_update_op_hash,
            }),
            predecessors: Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned()),
            doc_id: self.doc_id,
        };
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.record_bridge(&signed_op);
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Whether we have a bridge encrypting the `pcs_key_hash` secret under `under`.
    fn has_bridge(&self, pcs_key_hash: &Digest<PcsKey>, under: &Digest<PcsKey>) -> bool {
        self.bridges
            .get(pcs_key_hash)
            .is_some_and(|bridges| bridges.iter().any(|bridge| bridge.under == *under))
    }

    /// If there is a bridge, record it under the root secret it wraps.
    fn record_bridge(&mut self, op: &Signed<CgkaOperation>) {
        let CgkaOperation::Bridge { bridge, .. } = &op.payload else {
            return;
        };
        let bridge = bridge.as_ref();
        let stored = self.bridges.entry(bridge.pcs_key_hash).or_default();
        if !stored.contains(bridge) {
            stored.push(bridge.clone());
        }
    }

    /// If there is an invitation, record it for the id it targets.
    fn record_invitation(&mut self, op: &Signed<CgkaOperation>) {
        let CgkaOperation::Invite { invitation, .. } = &op.payload else {
            return;
        };
        let invitation = invitation.as_ref();
        let stored = self.invitations.entry(invitation.invitee_id).or_default();
        if !stored.contains(invitation) {
            stored.push(invitation.clone());
        }
    }

    /// Remove member from group.
    #[instrument(skip_all)]
    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: MemberId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        if !self.tree.contains_id(&id) {
            return Ok(None);
        }
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        if self.group_size() == 1 {
            return Err(CgkaError::RemoveLastMember);
        }
        let (leaf_idx, removed_keys) = self.tree.remove_id(id)?;
        let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
        let op = CgkaOperation::Remove {
            id,
            leaf_idx,
            removed_keys,
            predecessors,
            doc_id: self.doc_id,
        };
        let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
        self.ops_graph.add_local_op(&signed_op);
        Ok(Some(signed_op))
    }

    /// Update leaf key pair for this Identifier.
    /// This also triggers a tree path update for that leaf.
    /// If the owner is not in the tree but Public is, falls back to
    /// encrypting from Public's leaf using Public's well-known keys.
    #[instrument(skip_all)]
    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>), CgkaError> {
        if self.should_replay() {
            self.replay_ops_graph()?;
        }
        let (update_id, update_pk, update_sk) = if self.tree.contains_id(&self.owner_id) {
            (self.owner_id, new_pk, new_sk)
        } else {
            let public_id = MemberId::public();
            let NodeKey::ShareKey(pk) = self
                .tree
                .node_key_for_id(public_id)
                .map_err(|_| CgkaError::IdentifierNotFound)?
            else {
                return Err(CgkaError::ShareKeyNotFound);
            };
            let sk = *self.owner_sks.get(&pk).ok_or(CgkaError::ShareKeyNotFound)?;
            (public_id, pk, sk)
        };
        self.owner_sks.insert(update_pk, update_sk);
        let maybe_key_and_path =
            self.tree
                .encrypt_path(update_id, update_pk, &mut self.owner_sks, csprng)?;
        if let Some((pcs_key, new_path)) = maybe_key_and_path {
            let predecessors = Vec::from_iter(self.ops_graph.cgka_op_heads.iter().cloned());
            let op = CgkaOperation::Update {
                id: update_id,
                new_path: alloc::boxed::Box::new(new_path),
                predecessors,
                doc_id: self.doc_id,
            };

            let signed_op = async_signer::try_sign_async::<F, _, _>(signer, op).await?;
            self.ops_graph.add_local_op(&signed_op);
            self.insert_pcs_key(&pcs_key, Digest::hash(&signed_op));
            Ok((pcs_key, signed_op))
        } else {
            Err(CgkaError::IdentifierNotFound)
        }
    }

    /// The current group size
    pub fn group_size(&self) -> u32 {
        self.tree.member_count()
    }

    /// The members currently in the tree.
    pub fn member_ids(&self) -> impl Iterator<Item = MemberId> + '_ {
        self.tree.member_ids()
    }

    /// Merges concurrent [`CgkaOperation`]. Returns `Ok(true)` if merge is successful.
    ///
    /// If we receive a concurrent membership change (i.e., add or remove), then
    /// we add it to our ops graph but don't apply it yet. If there are no outstanding
    /// membership changes and we receive a concurrent update, we can apply it
    /// immediately.
    #[instrument(skip_all)]
    pub fn merge_concurrent_operation(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(false);
        }
        let predecessors = op.payload.predecessors();
        if !self.ops_graph.contains_predecessors(&predecessors) {
            return Err(CgkaError::OutOfOrderOperation);
        }
        self.record_invitation(&op);
        self.record_bridge(&op);
        let is_concurrent = !self.ops_graph.heads_contained_in(&predecessors);
        if is_concurrent {
            if self.pending_ops_for_structural_change {
                self.ops_graph.add_op(&op, &predecessors);
            } else if matches!(
                op.payload,
                CgkaOperation::Add { .. } | CgkaOperation::Remove { .. }
            ) {
                self.pending_ops_for_structural_change = true;
                self.ops_graph.add_op(&op, &predecessors);
            } else {
                self.apply_operation(op)?;
            }
        } else {
            if self.should_replay() {
                self.replay_ops_graph()?;
            }
            self.apply_operation(op)?;
        }
        Ok(true)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.ops_graph.topsort_graph()
    }

    pub fn contains_predecessors(&self, preds: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.ops_graph.contains_predecessors(preds)
    }

    /// Apply a [`CgkaOperation`].
    #[instrument(skip_all)]
    fn apply_operation(&mut self, op: Arc<Signed<CgkaOperation>>) -> Result<(), CgkaError> {
        if self.ops_graph.contains_op_hash(&Digest::hash(&op)) {
            return Ok(());
        }
        match op.payload {
            CgkaOperation::Add { added_id, pk, .. } => {
                self.tree.push_leaf(added_id, pk.into());
            }
            CgkaOperation::Remove { id, .. } => {
                self.tree.remove_id(id)?;
            }
            CgkaOperation::Update { ref new_path, .. } => {
                self.tree.apply_path(new_path);
            }
            CgkaOperation::Invite { .. } => self.record_invitation(&op),
            CgkaOperation::Bridge { .. } => self.record_bridge(&op),
        }
        self.ops_graph.add_op(&op, &op.payload.predecessors());
        Ok(())
    }

    /// Apply operations grouped into "epochs", where each epoch contains an ordered
    /// set of concurrent operations.
    #[instrument(skip_all)]
    fn apply_epochs(&mut self, epochs: &NonEmpty<CgkaEpoch>) -> Result<(), CgkaError> {
        for epoch in epochs {
            if epoch.len() == 1 {
                self.apply_operation(epoch[0].clone())?;
            } else {
                // If no operation in this epoch changes the tree's structure, we can
                // apply them directly and move on to the next epoch.
                if epoch.iter().all(|op| {
                    matches!(
                        op.payload,
                        CgkaOperation::Update { .. }
                            | CgkaOperation::Invite { .. }
                            | CgkaOperation::Bridge { .. }
                    )
                }) {
                    for op in epoch.iter() {
                        self.apply_operation(op.clone())?;
                    }
                    continue;
                }

                // An epoch with at least one membership change requires blanking
                // removed paths and sorting added leaves after all ops are applied.
                let mut added_ids = Set::new();
                let mut removed_ids = Set::new();
                for op in epoch.iter() {
                    match op.payload {
                        CgkaOperation::Add { added_id, .. } => {
                            added_ids.insert(added_id);
                        }
                        CgkaOperation::Remove { id, leaf_idx, .. } => {
                            removed_ids.insert((id, leaf_idx));
                        }
                        _ => {}
                    }
                    self.apply_operation(op.clone())?;
                }
                self.tree
                    .sort_leaves_and_blank_paths_for_concurrent_membership_changes(
                        added_ids,
                        removed_ids,
                    );
            }
        }
        Ok(())
    }

    /// Decrypt tree secret to derive [`PcsKey`].
    pub fn pcs_key_from_tree_root(&mut self) -> Result<PcsKey, CgkaError> {
        let key = match self
            .tree
            .decrypt_tree_secret(self.owner_id, &mut self.owner_sks)
        {
            Ok(k) => k,
            Err(e) => {
                // When deriving as the owner fails and Public is a member, read as
                // Public instead.
                let public = MemberId::public();
                if self.owner_id != public && self.tree.contains_id(&public) {
                    self.tree.decrypt_tree_secret(public, &mut self.owner_sks)?
                } else {
                    return Err(e);
                }
            }
        };
        Ok(PcsKey::new(key))
    }

    /// Derive [`PcsKey`] for provided hashes.
    ///
    /// If we have not seen this [`PcsKey`] before, we'll need to rebuild
    /// the tree state for its corresponding update operation.
    #[instrument(skip_all)]
    fn pcs_key_from_hashes(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if let Some(pcs_key) = self.pcs_keys.get(pcs_key_hash) {
            return Ok(*pcs_key.clone());
        }
        if self.has_pcs_key() {
            if let Ok(pcs_key) = self.pcs_key_from_tree_root() {
                if &Digest::hash(&pcs_key) == pcs_key_hash {
                    return Ok(pcs_key);
                }
            }
        }

        // An invitation or a bridge may already contain this key, in which case we
        // don't require a rebuild.
        if let Some(pcs_key) = self.pcs_key_from_invitation(pcs_key_hash) {
            self.insert_pcs_key(&pcs_key, *update_op_hash);
            return Ok(pcs_key);
        }
        if let Some(pcs_key) = self.pcs_key_from_bridge(pcs_key_hash, &mut Set::new()) {
            self.insert_pcs_key(&pcs_key, *update_op_hash);
            return Ok(pcs_key);
        }

        self.derive_pcs_key_for_op(update_op_hash)
    }

    /// Return this PCS key if we can derive it through a bridge. Return `None`
    /// otherwise.
    ///
    /// It's possible we can derive a key through a chain of bridges, but there
    /// could be cycles. `seen` ensures the traversal terminates.
    #[instrument(skip_all)]
    fn pcs_key_from_bridge(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        seen: &mut Set<Digest<PcsKey>>,
    ) -> Option<PcsKey> {
        if !seen.insert(*pcs_key_hash) {
            return None;
        }
        let bridges = self.bridges.get(pcs_key_hash)?.clone();
        for bridge in bridges {
            let Some(under) = self.encryption_pcs_key_for(&bridge, seen) else {
                continue;
            };
            let Ok(plaintext) = under.derive_bridge_key().try_open(&bridge.root_secret) else {
                continue;
            };
            let Ok(bytes) = <[u8; 32]>::try_from(plaintext) else {
                continue;
            };
            let pcs_key = PcsKey::new(ShareSecretKey::force_from_bytes(bytes));
            // Before returning, validate that the bridged key actually
            // corresponds to the hash that was passed in.
            if Digest::hash(&pcs_key) == *pcs_key_hash {
                debug!("recovered a root secret from a bridge");
                return Some(pcs_key);
            }
        }
        None
    }

    /// The secret used to encrypt the root secret wrapped by `bridge`.
    fn encryption_pcs_key_for(
        &mut self,
        bridge: &Bridge,
        seen: &mut Set<Digest<PcsKey>>,
    ) -> Option<PcsKey> {
        if let Some(pcs_key) = self.pcs_keys.get(&bridge.under) {
            return Some(**pcs_key);
        }
        if let Some(pcs_key) = self.pcs_key_from_invitation(&bridge.under) {
            return Some(pcs_key);
        }
        if let Ok(pcs_key) = self.derive_pcs_key_for_op(&bridge.under_update_op_hash) {
            return Some(pcs_key);
        }
        self.pcs_key_from_bridge(&bridge.under, seen)
    }

    /// Return this PCS key if we have it in an invitation and `None` otherwise.
    #[instrument(skip_all)]
    fn pcs_key_from_invitation(&self, pcs_key_hash: &Digest<PcsKey>) -> Option<PcsKey> {
        let addressed_to_us = [self.owner_id, MemberId::public()]
            .into_iter()
            .filter_map(|id| self.invitations.get(&id))
            .flatten();
        for invitation in addressed_to_us {
            if invitation.pcs_key_hash != *pcs_key_hash {
                continue;
            }
            let Ok(plaintext) = self
                .owner_sks
                .try_decrypt_encryption(invitation.inviter_pk, &invitation.root_secret)
            else {
                continue;
            };
            let Ok(bytes) = <[u8; 32]>::try_from(plaintext) else {
                continue;
            };
            let pcs_key = PcsKey::new(ShareSecretKey::force_from_bytes(bytes));
            // Before returning, validate that the invitation key actually
            // corresponds to the hash that was passed in.
            if Digest::hash(&pcs_key) == *pcs_key_hash {
                info!("recovered a root secret from an invitation");
                return Some(pcs_key);
            }
        }
        None
    }

    /// Derive [`PcsKey`] for this operation hash.
    #[instrument(skip_all)]
    fn derive_pcs_key_for_op(
        &mut self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        if !self.ops_graph.contains_op_hash(op_hash) {
            return Err(CgkaError::UnknownPcsKey);
        }
        let mut heads = Set::new();
        heads.insert(*op_hash);
        let ops = self.ops_graph.topsort_for_heads(&heads)?;
        self.rebuild_pcs_key(ops)
    }

    /// Whether we have unresolved concurrency that requires a replay to resolve.
    fn should_replay(&self) -> bool {
        !self.ops_graph.cgka_op_heads.is_empty()
            && (self.pending_ops_for_structural_change || !self.ops_graph.has_single_head())
    }

    /// Replay all ops in our graph in a deterministic order.
    #[instrument(skip_all)]
    fn replay_ops_graph(&mut self) -> Result<(), CgkaError> {
        let ordered_ops = self.ops_graph.topsort_graph()?;
        let rebuilt_cgka = self.rebuild_cgka(ordered_ops)?;
        self.update_cgka_from(&rebuilt_cgka);
        self.pending_ops_for_structural_change = false;
        Ok(())
    }

    /// Build a new [`Cgka`] for the provided non-empty list of [`CgkaEpoch`]s.
    #[instrument(skip_all)]
    fn rebuild_cgka(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<Cgka, CgkaError> {
        let mut rebuilt_cgka = Cgka::new_from_init_add(
            self.doc_id,
            self.original_member.0,
            self.original_member.1,
            self.init_add_op.clone(),
        )?
        .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        rebuilt_cgka.apply_epochs(&epochs)?;
        if rebuilt_cgka.has_pcs_key() {
            let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
            rebuilt_cgka.insert_pcs_key(&pcs_key, Digest::hash(&epochs.last()[0]));
        }
        Ok(rebuilt_cgka)
    }

    /// Derive a [`PcsKey`] by rebuilding a [`Cgka`] from the provided non-empty
    /// list of [`CgkaEpoch`]s.
    #[instrument(skip_all)]
    fn rebuild_pcs_key(&mut self, epochs: NonEmpty<CgkaEpoch>) -> Result<PcsKey, CgkaError> {
        debug_assert!(matches!(
            epochs.last()[0].payload,
            CgkaOperation::Update { .. }
        ));
        let mut rebuilt_cgka = Cgka::new_from_init_add(
            self.doc_id,
            self.original_member.0,
            self.original_member.1,
            self.init_add_op.clone(),
        )?
        .with_new_owner(self.owner_id, self.owner_sks.clone())?;
        rebuilt_cgka.apply_epochs(&epochs)?;
        let pcs_key = rebuilt_cgka.pcs_key_from_tree_root()?;
        self.insert_pcs_key(&pcs_key, Digest::hash(&epochs.last()[0]));
        Ok(pcs_key)
    }

    #[instrument(skip_all)]
    fn insert_pcs_key(&mut self, pcs_key: &PcsKey, op_hash: Digest<Signed<CgkaOperation>>) {
        let digest = Digest::hash(pcs_key);
        info!("{:?}", digest);
        self.pcs_key_ops.insert(digest, op_hash);
        self.pcs_keys.insert((*pcs_key).into());
    }

    /// Record a PCS key that was used to encrypt content. If it's the latest
    /// such key we know of, record it as `newest_encrypting_pcs_key`.
    fn record_encrypting_pcs_key(
        &mut self,
        pcs_key: &PcsKey,
        op_hash: Digest<Signed<CgkaOperation>>,
    ) {
        let hash = Digest::hash(pcs_key);
        if !self.pcs_keys.contains_key(&hash) {
            self.insert_pcs_key(pcs_key, op_hash);
        }
        if Some(hash) == self.newest_encrypting_pcs_key {
            return;
        }
        if self.is_later_than_newest_encrypting_key(&op_hash) {
            self.newest_encrypting_pcs_key = Some(hash);
        }
    }

    fn is_later_than_newest_encrypting_key(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> bool {
        let Some(last) = self.newest_encrypting_pcs_key else {
            return true;
        };
        let Some(last_op) = self.pcs_key_ops.get(&last) else {
            return true;
        };
        let Some(last_lamport_ts) = self.ops_graph.lamport_ts_for(last_op) else {
            return true;
        };
        self.ops_graph
            .lamport_ts_for(op_hash)
            .is_some_and(|lamport| lamport > last_lamport_ts)
    }

    /// Extend our state with that of the provided [`Cgka`].
    #[instrument(skip_all)]
    fn update_cgka_from(&mut self, other: &Self) {
        self.tree = other.tree.clone();
        self.owner_sks.extend(&other.owner_sks);
        self.pcs_keys.extend(
            other
                .pcs_keys
                .iter()
                .map(|(hash, key)| (*hash, key.clone())),
        );
        self.pcs_key_ops.extend(other.pcs_key_ops.iter());
        self.receive_invitations(&other.invitations);
        self.receive_bridges(&other.bridges);
        self.pending_ops_for_structural_change = other.pending_ops_for_structural_change;
    }

    fn receive_invitations(&mut self, other: &Map<MemberId, Vec<Invitation>>) {
        for (member, invitations) in other.iter() {
            let stored = self.invitations.entry(*member).or_default();
            for invitation in invitations {
                if !stored.contains(invitation) {
                    stored.push(invitation.clone());
                }
            }
        }
    }

    fn receive_bridges(&mut self, other: &Map<Digest<PcsKey>, Vec<Bridge>>) {
        for (pcs_key_hash, bridges) in other.iter() {
            let stored = self.bridges.entry(*pcs_key_hash).or_default();
            for bridge in bridges {
                if !stored.contains(bridge) {
                    stored.push(bridge.clone());
                }
            }
        }
    }
}

impl Fork for Cgka {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for Cgka {
    fn merge(&mut self, fork: Self::Forked) {
        self.owner_sks.merge(fork.owner_sks);
        self.ops_graph.merge(fork.ops_graph);
        self.pcs_keys.merge(fork.pcs_keys);
        self.pcs_key_ops.extend(fork.pcs_key_ops.iter());
        self.receive_invitations(&fork.invitations);
        self.receive_bridges(&fork.bridges);
        // The fork may have reached content we did not, so take its newest encrypting
        // key only if it comes later than ours.
        if let Some(hash) = fork.newest_encrypting_pcs_key {
            if let Some(op_hash) = self.pcs_key_ops.get(&hash).copied() {
                if self.is_later_than_newest_encrypting_key(&op_hash) {
                    self.newest_encrypting_pcs_key = Some(hash);
                }
            }
        }
        self.replay_ops_graph()
            .expect("two valid graphs should always merge causal consistency");
    }
}

#[cfg(feature = "test_utils")]
impl Cgka {
    pub fn secret_from_root(&mut self) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_tree_root()
    }

    pub fn secret(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        self.pcs_key_from_hashes(pcs_key_hash, update_op_hash)
    }
}
