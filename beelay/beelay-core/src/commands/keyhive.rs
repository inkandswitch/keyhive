use std::collections::HashMap;

use error::AddMember;
use keyhive_core::{
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::public::Public,
};

use crate::{contact_card::ContactCard, io::Signer, CommitHash, DocumentId, PeerId, TaskContext};

#[derive(Debug)]
pub enum KeyhiveCommand {
    CreateGroup(Vec<KeyhiveEntityId>),
    CreateContactCard,
    AddMemberToGroup(AddMemberToGroup),
    RemoveMemberFromGroup(RemoveMemberFromGroup),
    AddMemberToDoc(DocumentId, KeyhiveEntityId, MemberAccess),
    RemoveMemberFromDoc(DocumentId, KeyhiveEntityId),
    QueryAccess(DocumentId),
    #[cfg(feature = "debug_events")]
    DebugEvents(keyhive_core::debug_events::Nicknames),
}

#[derive(Debug)]
pub enum KeyhiveCommandResult {
    CreateGroup(Result<PeerId, error::CreateGroup>),
    CreateContactCard(Result<ContactCard, error::CreateContactCard>),
    AddMemberToGroup(Result<(), error::AddMember>),
    RemoveMemberFromGroup(Result<(), error::RemoveMember>),
    AddMemberToDoc,
    RemoveMemberFromDoc(Result<(), error::RemoveMember>),
    QueryAccess(Result<HashMap<PeerId, MemberAccess>, error::QueryAccess>),
    #[cfg(feature = "debug_events")]
    DebugEvents(keyhive_core::debug_events::DebugEventTable),
}

#[derive(Debug)]
pub enum Access {
    Public,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemberAccess {
    Pull,
    Read,
    Write,
    Admin,
}

impl std::fmt::Display for MemberAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemberAccess::Pull => write!(f, "pull"),
            MemberAccess::Read => write!(f, "read"),
            MemberAccess::Write => write!(f, "write"),
            MemberAccess::Admin => write!(f, "admin"),
        }
    }
}

impl From<MemberAccess> for keyhive_core::access::Access {
    fn from(access: MemberAccess) -> Self {
        match access {
            MemberAccess::Pull => keyhive_core::access::Access::Pull,
            MemberAccess::Read => keyhive_core::access::Access::Read,
            MemberAccess::Write => keyhive_core::access::Access::Write,
            MemberAccess::Admin => keyhive_core::access::Access::Admin,
        }
    }
}

impl From<keyhive_core::access::Access> for MemberAccess {
    fn from(value: keyhive_core::access::Access) -> Self {
        match value {
            keyhive_core::access::Access::Pull => MemberAccess::Pull,
            keyhive_core::access::Access::Read => MemberAccess::Read,
            keyhive_core::access::Access::Write => MemberAccess::Write,
            keyhive_core::access::Access::Admin => MemberAccess::Admin,
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub enum KeyhiveEntityId {
    Individual(ContactCard),
    Group(PeerId),
    Doc(DocumentId),
    Public,
}

impl std::fmt::Display for KeyhiveEntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyhiveEntityId::Individual(peer_id) => write!(f, "peer:{}", peer_id),
            KeyhiveEntityId::Group(group_id) => write!(f, "group:{}", group_id),
            KeyhiveEntityId::Doc(doc_id) => write!(f, "doc:{}", doc_id),
            KeyhiveEntityId::Public => write!(f, "public"),
        }
    }
}

impl From<ContactCard> for KeyhiveEntityId {
    fn from(contact_card: ContactCard) -> Self {
        KeyhiveEntityId::Individual(contact_card)
    }
}

impl From<PeerId> for KeyhiveEntityId {
    fn from(peer_id: PeerId) -> Self {
        KeyhiveEntityId::Group(peer_id)
    }
}

impl From<DocumentId> for KeyhiveEntityId {
    fn from(doc_id: DocumentId) -> Self {
        KeyhiveEntityId::Doc(doc_id)
    }
}

impl From<Public> for KeyhiveEntityId {
    fn from(_public: Public) -> Self {
        KeyhiveEntityId::Public
    }
}

pub(crate) async fn handle_keyhive_command<R>(
    ctx: TaskContext<R>,
    command: KeyhiveCommand,
) -> KeyhiveCommandResult
where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    match command {
        KeyhiveCommand::AddMemberToDoc(doc_id, contact_card, access) => {
            add_member_to_doc(ctx, doc_id, contact_card, access).await;
            KeyhiveCommandResult::AddMemberToDoc
        }
        KeyhiveCommand::RemoveMemberFromDoc(doc_id, peer_id) => {
            let result = remove_member_from_doc(ctx, doc_id, peer_id).await;
            KeyhiveCommandResult::RemoveMemberFromDoc(result)
        }
        KeyhiveCommand::QueryAccess(doc_id) => {
            let result = ctx
                .state()
                .keyhive()
                .query_access(doc_id)
                .await
                .ok_or(error::QueryAccess::NoSuchDocument);
            KeyhiveCommandResult::QueryAccess(result)
        }
        KeyhiveCommand::CreateGroup(other_parents) => {
            let result = ctx
                .state()
                .keyhive()
                .create_group(other_parents)
                .await
                .map_err(|e| e.into());
            KeyhiveCommandResult::CreateGroup(result)
        }
        KeyhiveCommand::AddMemberToGroup(add) => {
            let result = add_member_to_group(ctx, add).await;
            KeyhiveCommandResult::AddMemberToGroup(result)
        }
        KeyhiveCommand::RemoveMemberFromGroup(remove) => {
            let result = remove_member_from_group(ctx, remove).await;
            KeyhiveCommandResult::RemoveMemberFromGroup(result)
        }
        #[cfg(feature = "debug_events")]
        KeyhiveCommand::DebugEvents(nicknames) => {
            let result = ctx.state().keyhive().debug_events(nicknames).await;
            KeyhiveCommandResult::DebugEvents(result)
        }
        KeyhiveCommand::CreateContactCard => {
            let result = ctx
                .state()
                .keyhive()
                .contact_card()
                .await
                .map_err(error::CreateContactCard::from);
            KeyhiveCommandResult::CreateContactCard(result)
        }
    }
}

#[tracing::instrument(skip(ctx, peer_to_add),fields(peer_to_add=%peer_to_add))]
async fn add_member_to_doc<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    peer_to_add: KeyhiveEntityId,
    access: MemberAccess,
) {
    tracing::debug!("adding member to document");
    if let Some(agent) = ctx.state().keyhive().get_agent(peer_to_add).await {
        ctx.state()
            .keyhive()
            .add_member_to_doc(doc_id, agent, access.into())
            .await;
    } else {
        tracing::error!("member not found");
    }
}

#[tracing::instrument(skip(ctx, peer_to_remove),fields(peer_to_remove=%peer_to_remove))]
async fn remove_member_from_doc<R>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    peer_to_remove: KeyhiveEntityId,
) -> Result<(), error::RemoveMember>
where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    tracing::debug!("removing member from document");
    ctx.state()
        .keyhive()
        .remove_member_from_doc(doc_id, peer_to_remove)
        .await
        .map_err(|e| error::RemoveMember(e.to_string()))?;
    Ok(())
}

#[derive(Debug)]
pub struct AddMemberToGroup {
    pub group_id: PeerId,
    pub member: KeyhiveEntityId,
    pub access: MemberAccess,
}

#[tracing::instrument(skip(ctx),fields(group_id=%group_id, member_id=%member))]
async fn add_member_to_group<R>(
    ctx: TaskContext<R>,
    AddMemberToGroup {
        group_id,
        member,
        access,
    }: AddMemberToGroup,
) -> Result<(), error::AddMember>
where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    tracing::debug!("adding member to group");
    if let Some(agent) = ctx.state().keyhive().get_agent(member).await {
        ctx.state()
            .keyhive()
            .add_member_to_group(group_id, agent, access.into())
            .await;
        Ok(())
    } else {
        tracing::error!("member not found");
        Err(AddMember::MemberNotFound)
    }
}

#[derive(Debug)]
pub struct RemoveMemberFromGroup {
    pub group_id: PeerId,
    pub member: KeyhiveEntityId,
}

#[tracing::instrument(skip(ctx, member))]
async fn remove_member_from_group<R>(
    ctx: TaskContext<R>,
    RemoveMemberFromGroup { group_id, member }: RemoveMemberFromGroup,
) -> Result<(), error::RemoveMember>
where
    R: rand::Rng + rand::CryptoRng + 'static,
{
    tracing::debug!("removing member from group");
    if let Some(agent) = ctx.state().keyhive().get_agent(member).await {
        ctx.state()
            .keyhive()
            .remove_member_from_group(group_id, agent)
            .await
            .map_err(|e| error::RemoveMember(e.to_string()))
    } else {
        tracing::error!("member not found");
        Ok(())
    }
}

pub(crate) mod error {
    #[derive(Debug, thiserror::Error)]
    pub enum AddMember {
        #[error("peer not found")]
        MemberNotFound,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    pub struct RemoveMember(pub(super) String);

    #[derive(Debug, thiserror::Error)]
    pub enum QueryAccess {
        #[error("document not found")]
        NoSuchDocument,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("error creating group: {0}")]
    pub struct CreateGroup(String);

    impl From<keyhive_core::crypto::signed::SigningError> for CreateGroup {
        fn from(e: keyhive_core::crypto::signed::SigningError) -> Self {
            Self(e.to_string())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("error creating contact card: {0}")]
    pub struct CreateContactCard(String);

    impl From<keyhive_core::crypto::signed::SigningError> for CreateContactCard {
        fn from(e: keyhive_core::crypto::signed::SigningError) -> Self {
            Self(e.to_string())
        }
    }
}

mod encoding {
    use keyhive_core::{
        event::static_event::StaticEvent,
        principal::group::membership_operation::StaticMembershipOperation,
    };

    use crate::{
        serialization::{leb128, parse, Encode, Parse},
        CommitHash,
    };

    impl Encode for StaticMembershipOperation<CommitHash> {
        fn encode_into(&self, out: &mut Vec<u8>) {
            let serialized = bincode::serialize(&self).unwrap();
            leb128::encode_uleb128(out, serialized.len() as u64);
            out.extend(serialized);
        }
    }

    impl<'a> Parse<'a> for StaticMembershipOperation<CommitHash> {
        fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
            let (input, payload) = parse::slice(input)?;
            let deserialized = bincode::deserialize(payload)
                .map_err(|e| input.error(format!("unable to parse static operation: {}", e)))?;
            Ok((input, deserialized))
        }
    }

    impl Encode for StaticEvent<CommitHash> {
        fn encode_into(&self, out: &mut Vec<u8>) {
            let serialized = bincode::serialize(&self).unwrap();
            leb128::encode_uleb128(out, serialized.len() as u64);
            out.extend(serialized);
        }
    }

    impl<'a> Parse<'a> for StaticEvent<CommitHash> {
        fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
            let (input, payload) = parse::slice(input)?;
            let deserialized = bincode::deserialize(payload)
                .map_err(|e| input.error(format!("unable to parse static event: {}", e)))?;
            Ok((input, deserialized))
        }
    }

    impl Encode for keyhive_core::principal::identifier::Identifier {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(self.0.as_bytes());
        }
    }

    impl<'a> Parse<'a> for keyhive_core::principal::identifier::Identifier {
        fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
            let (input, bytes) = parse::arr::<32>(input)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|e| input.error(format!("unable to parse identifier: {}", e)))?;
            let id = keyhive_core::principal::identifier::Identifier::from(key);
            Ok((input, id))
        }
    }
}

#[derive(Clone)]
pub(crate) struct Listener {
    send: futures::channel::mpsc::UnboundedSender<
        keyhive_core::event::Event<Signer, CommitHash, Listener>,
    >,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish()
    }
}

impl Listener {
    pub(crate) fn new(
        send: futures::channel::mpsc::UnboundedSender<
            keyhive_core::event::Event<Signer, CommitHash, Listener>,
        >,
    ) -> Self {
        Self { send }
    }
}

impl PrekeyListener for Listener {
    async fn on_prekeys_expanded(
        &self,
        new_prekey: &std::rc::Rc<
            keyhive_core::crypto::signed::Signed<
                keyhive_core::principal::individual::op::add_key::AddKeyOp,
            >,
        >,
    ) {
        let _ =
            self.send
                .unbounded_send(keyhive_core::event::Event::<Signer, CommitHash, _>::from(
                    new_prekey.clone(),
                ));
    }

    async fn on_prekey_rotated(
        &self,
        rotate_key: &std::rc::Rc<
            keyhive_core::crypto::signed::Signed<
                keyhive_core::principal::individual::op::rotate_key::RotateKeyOp,
            >,
        >,
    ) {
        let _ =
            self.send
                .unbounded_send(keyhive_core::event::Event::<Signer, CommitHash, _>::from(
                    rotate_key.clone(),
                ));
    }
}

impl MembershipListener<Signer, CommitHash> for Listener {
    async fn on_delegation(
        &self,
        data: &std::rc::Rc<
            keyhive_core::crypto::signed::Signed<
                keyhive_core::principal::group::delegation::Delegation<Signer, CommitHash, Self>,
            >,
        >,
    ) {
        self.send
            .unbounded_send(keyhive_core::event::Event::from(data.clone()))
            .unwrap();
    }

    async fn on_revocation(
        &self,
        data: &std::rc::Rc<
            keyhive_core::crypto::signed::Signed<
                keyhive_core::principal::group::revocation::Revocation<Signer, CommitHash, Self>,
            >,
        >,
    ) {
        let _ = self
            .send
            .unbounded_send(keyhive_core::event::Event::from(data.clone()));
    }
}

impl CgkaListener for Listener {
    async fn on_cgka_op(
        &self,
        data: &std::rc::Rc<
            keyhive_core::crypto::signed::Signed<keyhive_core::cgka::operation::CgkaOperation>,
        >,
    ) {
        self.send
            .unbounded_send(keyhive_core::event::Event::from(data.clone()))
            .unwrap();
    }
}
