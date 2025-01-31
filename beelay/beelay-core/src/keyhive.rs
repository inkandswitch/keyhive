use std::collections::HashMap;

use error::AddMember;

use crate::{
    keyhive_sync::sync_keyhive, state::TaskContext, sync_docs::sync_doc, DocumentId, PeerId,
};

#[derive(Debug)]
pub enum KeyhiveCommand {
    AddMember(DocumentId, PeerId, MemberAccess),
    RemoveMember(DocumentId, PeerId),
    QueryAccess(DocumentId),
}

#[derive(Debug)]
pub enum KeyhiveCommandResult {
    AddMember(Result<(), error::AddMember>),
    RemoveMember(Result<(), error::RemoveMember>),
    QueryAccess(Result<HashMap<PeerId, MemberAccess>, error::QueryAccess>),
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

pub(crate) async fn handle_keyhive_command<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    command: KeyhiveCommand,
) -> KeyhiveCommandResult {
    match command {
        KeyhiveCommand::AddMember(doc_id, peer_id, access) => {
            let result = add_member(ctx, doc_id, peer_id, access).await;
            KeyhiveCommandResult::AddMember(result)
        }
        KeyhiveCommand::RemoveMember(doc_id, peer_id) => {
            let result = remove_member(ctx, doc_id, peer_id).await;
            KeyhiveCommandResult::RemoveMember(result)
        }
        KeyhiveCommand::QueryAccess(doc_id) => {
            let result = ctx
                .keyhive()
                .query_access(doc_id)
                .ok_or(error::QueryAccess::NoSuchDocument);
            KeyhiveCommandResult::QueryAccess(result)
        }
    }
}

#[tracing::instrument(skip(ctx, peer_id),fields(peer_id=%peer_id))]
async fn add_member<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    peer_id: PeerId,
    access: MemberAccess,
) -> Result<(), error::AddMember> {
    tracing::debug!("adding member to document");
    ctx.keyhive().register_peer(peer_id);
    if let Some(agent) = ctx.keyhive().get_peer(peer_id) {
        ctx.keyhive().add_member(doc_id, agent, access.into());
        // Spawn tasks to upload new ops to forwarding peers
        crate::keyhive_sync::sync_keyhive_with_forwarding_peers(ctx.clone(), vec![peer_id]).await;
        tracing::trace!("rerunning sync for document with forwarding peers");
        for peer in ctx.forwarding_peers() {
            let doc_id = doc_id.clone();
            ctx.spawn(move |ctx| async move {
                if let Err(e) = sync_doc(ctx, peer, doc_id).await {
                    tracing::error!(err=?e, "error syncing document");
                }
            });
        }
        return Ok(());
    }
    tracing::trace!(?doc_id, %peer_id, "agent not found locally, requesting from forwarding peers");
    crate::keyhive_sync::sync_keyhive_with_forwarding_peers(ctx.clone(), vec![peer_id]).await;
    if let Some(agent) = ctx.keyhive().get_peer(peer_id) {
        tracing::trace!("agent found after requesting, adding to document");
        ctx.keyhive()
            .add_member(doc_id, agent, keyhive_core::access::Access::Write);
        // Spawn tasks to upload new ops to forwarding peers
        tracing::trace!("uploading new events to forwarding peers");
        crate::keyhive_sync::sync_keyhive_with_forwarding_peers(ctx.clone(), vec![peer_id]).await;
        tracing::trace!("rerunning sync for document with forwarding peers");
        for peer in ctx.forwarding_peers() {
            let doc_id = doc_id.clone();
            ctx.spawn(move |ctx| async move {
                if let Err(e) = sync_doc(ctx, peer, doc_id).await {
                    tracing::error!(err=?e, "error syncing document");
                }
            });
        }
        return Ok(());
    }
    return Err(AddMember::MemberNotFound);
}

#[tracing::instrument(skip(ctx, peer_id),fields(peer_id=%peer_id))]
async fn remove_member<R: rand::Rng + rand::CryptoRng + 'static>(
    ctx: TaskContext<R>,
    doc_id: DocumentId,
    peer_id: PeerId,
) -> Result<(), error::RemoveMember> {
    tracing::debug!("removing member from document");
    ctx.keyhive()
        .remove_member(doc_id, peer_id)
        .map_err(|e| error::RemoveMember(e.to_string()))?;
    let forwarding_peers = ctx.forwarding_peers();
    tracing::trace!("uploading new events to forwarding peers");
    let upload = futures::future::join_all(
        forwarding_peers
            .into_iter()
            .map(|peer| sync_keyhive(ctx.clone(), peer, Vec::new())),
    );
    upload.await;
    Ok(())
}

pub(crate) mod error {
    use keyhive_core::listener::no_listener::NoListener;

    use crate::CommitHash;

    #[derive(Debug, thiserror::Error)]
    pub enum AddMember {
        #[error("peer not found")]
        MemberNotFound,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    pub struct RemoveMember(pub(super) String);

    #[derive(Debug, thiserror::Error)]
    pub(crate) enum ReceiveEventError {
        #[error("missing dependency")]
        MissingDependency,
        #[error(transparent)]
        Receive(#[from] keyhive_core::keyhive::ReceiveEventError<CommitHash, NoListener>),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum QueryAccess {
        #[error("document not found")]
        NoSuchDocument,
    }
}

mod encoding {
    use keyhive_core::{
        event::StaticEvent, principal::group::membership_operation::StaticMembershipOperation,
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
