use crate::{
    blob::BlobMeta,
    network::{
        messages::{FetchedSedimentree, SessionResponse, UploadItem},
        PeerAddress, RpcError,
    },
    riblt,
    state::DocUpdateBuilder,
    CommitHash, DocumentId, PeerId, StorageKey, TaskContext,
};

pub(crate) mod server_session;
mod session_id;
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{digest::Digest, signed::Signed},
    event::static_event::StaticEvent,
};
use server_session::MakeSymbols;
pub(crate) use session_id::SessionId;
mod sync_doc;
pub(crate) use sync_doc::CgkaSymbol;
mod sync_docs;
pub(crate) use sync_docs::DocStateHash;
pub(crate) mod local_state;
pub(crate) use local_state::LocalState;
mod sync_membership;
pub(crate) use sync_membership::MembershipSymbol;
pub(crate) mod sessions;
pub(crate) use sessions::Sessions;

/// Combined trait for all sync operations
pub(crate) trait SyncEffects<R: rand::Rng + rand::CryptoRng> {
    /// The storage type used for sedimentree operations
    type Storage: crate::sedimentree::storage::Storage + Clone;

    /// Access to the target node for operations
    #[allow(dead_code)]
    fn target(&self) -> PeerAddress;

    /// Get the peer ID we're syncing with
    fn remote_peer_id(&self) -> &PeerId;

    /// Access to the keyhive
    fn keyhive<'a>(&'a self) -> crate::state::keyhive::KeyhiveCtx<'a, R>;

    /// Access to storage for a specific document
    fn sedimentree_storage(&self, doc_id: DocumentId) -> Self::Storage;

    // Membership sync methods
    /// Start a remote session
    async fn start_remote_session(
        &self,
    ) -> Result<
        (
            SessionId,
            Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>>,
        ),
        RpcError,
    >;

    /// Fetch membership symbols
    async fn fetch_membership_symbols(
        &self,
        session: SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>>>, RpcError>;

    /// Fetch membership operations
    async fn fetch_membership_ops(
        &self,
        session_id: SessionId,
        hashes: Vec<Digest<StaticEvent<CommitHash>>>,
    ) -> Result<SessionResponse<Vec<StaticEvent<CommitHash>>>, RpcError>;

    /// Upload membership operations
    async fn upload_membership_ops(
        &self,
        session: SessionId,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> Result<(), RpcError>;

    // Document sync methods
    /// Fetch document state symbols
    async fn fetch_doc_symbols(
        &self,
        session_id: SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_docs::DocStateHash>>>, RpcError>;

    /// Fetch the remote sedimentree
    async fn fetch_remote_tree(
        &self,
        doc: DocumentId,
    ) -> Result<Option<crate::sedimentree::SedimentreeSummary>, RpcError>;

    /// Fetch blob data
    async fn fetch_blob(
        &self,
        doc_id: DocumentId,
        blob: crate::BlobHash,
    ) -> Result<Option<Vec<u8>>, RpcError>;

    /// Upload a commit
    async fn upload_commit(
        &self,
        doc_id: DocumentId,
        commit: crate::sedimentree::LooseCommit,
        blob: Vec<u8>,
    ) -> Result<(), RpcError>;

    /// Upload a stratum
    async fn upload_stratum(
        &self,
        doc_id: DocumentId,
        stratum: crate::sedimentree::Stratum,
        blob: Vec<u8>,
    ) -> Result<(), RpcError>;

    /// Save a blob locally
    async fn save_blob(&self, contents: Vec<u8>);

    /// Fetch CGKA symbols
    async fn fetch_cgka_symbols(
        &self,
        session: SessionId,
        doc_id: DocumentId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_doc::CgkaSymbol>>>, RpcError>;

    /// Fetch CGKA operations
    async fn fetch_cgka_ops(
        &self,
        session: SessionId,
        doc_id: DocumentId,
        op_hashes: Vec<Digest<Signed<CgkaOperation>>>,
    ) -> Result<SessionResponse<Vec<Signed<CgkaOperation>>>, RpcError>;

    /// Upload CGKA operations
    async fn upload_cgka_ops(
        &self,
        session_id: SessionId,
        doc_id: DocumentId,
        ops: Vec<Signed<CgkaOperation>>,
    ) -> Result<(), RpcError>;

    /// Get local state information for sync
    async fn get_local_state(&self) -> Result<LocalState, local_state::Error>;

    /// Apply document updates from a builder
    fn apply_doc_update(&self, update: DocUpdateBuilder);

    fn mark_doc_changed(&self, doc_id: &DocumentId);
}

const MAX_RETRIES: usize = 2;

pub(crate) async fn sync<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
>(
    effects: E,
) -> Result<(), Error> {
    let mut retries = 0;
    loop {
        match sync_inner(effects.clone()).await {
            Ok(_) => return Ok(()),
            Err(err) => match err {
                MaybeSessionError::Expired => {
                    if retries < MAX_RETRIES {
                        tracing::warn!(?retries, "session expired, retrying");
                        retries += 1;
                        continue;
                    } else {
                        tracing::warn!(?retries, "session expired, giving up");
                    }
                }
                MaybeSessionError::NotFound => {
                    tracing::warn!("the other end said the session was not found");
                    return Err(Error::Session);
                }
                MaybeSessionError::Other(other) => return Err(other),
            },
        }
    }
}

pub(crate) async fn sync_inner<
    R: rand::Rng + rand::CryptoRng + Clone + 'static,
    E: SyncEffects<R> + Clone,
>(
    effects: E,
) -> Result<(), MaybeSessionError> {
    // Get local state information
    let local_state = effects.get_local_state().await?;

    // Start sync session
    let (session_id, first_membership_symbols) = effects
        .start_remote_session()
        .await
        .map_err(|_| Error::unable_to_reach_peer())?;

    // Sync membership operations
    sync_membership::sync_membership(
        effects.clone(),
        session_id,
        first_membership_symbols,
        local_state.membership_and_prekey_ops,
        effects.remote_peer_id().clone(),
    )
    .await?;

    // Sync document states
    let sync_docs::SyncDocsResult {
        out_of_sync,
        in_sync: _,
    } = sync_docs::sync_docs(
        effects.clone(),
        session_id,
        local_state.doc_states,
        effects.remote_peer_id().clone(),
    )
    .await?;

    tracing::trace!(?out_of_sync, "completed doc collection state sync");

    // Sync individual documents
    for doc_id in out_of_sync {
        // TODO: Do this concurrently
        sync_doc::sync_doc(effects.clone(), session_id, doc_id).await?;
    }

    Ok(())
}

#[derive(Clone)]
pub(crate) struct SyncContext<R: rand::Rng + rand::CryptoRng> {
    ctx: TaskContext<R>,
    target: PeerAddress,
    remote_peer_id: PeerId,
}

impl<R: rand::Rng + rand::CryptoRng> SyncContext<R> {
    pub(crate) fn new(ctx: TaskContext<R>, target: PeerAddress, remote_peer_id: PeerId) -> Self {
        Self {
            ctx,
            target,
            remote_peer_id,
        }
    }
}

impl<R: rand::Rng + rand::CryptoRng + Clone + 'static> SyncEffects<R> for SyncContext<R> {
    type Storage = crate::task_context::DocStorage;

    fn target(&self) -> PeerAddress {
        self.target
    }

    fn remote_peer_id(&self) -> &PeerId {
        &self.remote_peer_id
    }

    fn keyhive<'a>(&'a self) -> crate::state::keyhive::KeyhiveCtx<'a, R> {
        self.ctx.state().keyhive()
    }

    fn sedimentree_storage(&self, doc_id: DocumentId) -> Self::Storage {
        self.ctx.storage().doc_storage(doc_id)
    }

    async fn get_local_state(&self) -> Result<LocalState, local_state::Error> {
        LocalState::new(self.ctx.clone(), self.remote_peer_id.clone()).await
    }

    async fn start_remote_session(
        &self,
    ) -> Result<
        (
            SessionId,
            Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>>,
        ),
        RpcError,
    > {
        self.ctx.requests().begin_sync(self.target.clone()).await
    }

    async fn fetch_membership_symbols(
        &self,
        session: SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_membership::MembershipSymbol>>>, RpcError>
    {
        self.ctx
            .requests()
            .fetch_membership_symbols(self.target.clone(), session, make_symbols)
            .await
    }

    async fn fetch_membership_ops(
        &self,
        session_id: SessionId,
        hashes: Vec<Digest<StaticEvent<CommitHash>>>,
    ) -> Result<SessionResponse<Vec<StaticEvent<CommitHash>>>, RpcError> {
        self.ctx
            .requests()
            .download_membership_ops(self.target.clone(), session_id, hashes)
            .await
    }

    async fn upload_membership_ops(
        &self,
        session: SessionId,
        ops: Vec<StaticEvent<CommitHash>>,
    ) -> Result<(), RpcError> {
        self.ctx
            .requests()
            .upload_membership_ops(self.target.clone(), session, ops)
            .await
    }

    async fn fetch_doc_symbols(
        &self,
        session_id: SessionId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_docs::DocStateHash>>>, RpcError> {
        self.ctx
            .requests()
            .fetch_doc_state_symbols(self.target.clone(), session_id, make_symbols)
            .await
    }

    async fn fetch_remote_tree(
        &self,
        doc: DocumentId,
    ) -> Result<Option<crate::sedimentree::SedimentreeSummary>, RpcError> {
        let resp = self
            .ctx
            .requests()
            .fetch_sedimentrees(self.target.clone(), doc)
            .await?;
        Ok(match resp {
            FetchedSedimentree::Found(content) => Some(content),
            FetchedSedimentree::NotFound => None,
        })
    }

    async fn fetch_blob(
        &self,
        doc_id: DocumentId,
        blob: crate::BlobHash,
    ) -> Result<Option<Vec<u8>>, RpcError> {
        self.ctx
            .requests()
            .fetch_blob(self.target.clone(), doc_id, blob)
            .await
    }

    async fn upload_commit(
        &self,
        doc_id: DocumentId,
        commit: crate::sedimentree::LooseCommit,
        blob: Vec<u8>,
    ) -> Result<(), RpcError> {
        let data = UploadItem::commit(&commit, blob, None);
        self.ctx
            .requests()
            .upload_commits(self.target.clone(), doc_id, vec![data])
            .await
    }

    async fn upload_stratum(
        &self,
        doc_id: DocumentId,
        stratum: crate::sedimentree::Stratum,
        blob: Vec<u8>,
    ) -> Result<(), RpcError> {
        let data = UploadItem::stratum(&stratum, blob, None);
        self.ctx
            .requests()
            .upload_commits(self.target.clone(), doc_id, vec![data])
            .await
    }

    async fn save_blob(&self, contents: Vec<u8>) {
        let meta = BlobMeta::new(&contents);
        let key = StorageKey::blob(meta.hash());
        self.ctx.storage().put(key, contents).await;
    }

    async fn fetch_cgka_symbols(
        &self,
        session: SessionId,
        doc_id: DocumentId,
        make_symbols: MakeSymbols,
    ) -> Result<SessionResponse<Vec<riblt::CodedSymbol<sync_doc::CgkaSymbol>>>, RpcError> {
        self.ctx
            .requests()
            .fetch_cgka_symbols(self.target.clone(), session, doc_id, make_symbols)
            .await
    }

    async fn fetch_cgka_ops(
        &self,
        session: SessionId,
        doc_id: DocumentId,
        op_hashes: Vec<Digest<Signed<CgkaOperation>>>,
    ) -> Result<SessionResponse<Vec<Signed<CgkaOperation>>>, RpcError> {
        self.ctx
            .requests()
            .download_cgka_ops(self.target.clone(), session, doc_id, op_hashes)
            .await
    }

    async fn upload_cgka_ops(
        &self,
        session_id: SessionId,
        _doc_id: DocumentId,
        ops: Vec<Signed<CgkaOperation>>,
    ) -> Result<(), RpcError> {
        self.ctx
            .requests()
            .upload_cgka_ops(self.target.clone(), session_id, ops)
            .await
    }

    fn apply_doc_update(&self, update: DocUpdateBuilder) {
        self.ctx.state().docs().apply_doc_update(update);
    }

    fn mark_doc_changed(&self, doc_id: &DocumentId) {
        self.ctx.state().docs().mark_changed(doc_id);
    }
}

// Original entry point function that now delegates to the new implementation
pub(crate) async fn sync_with_peer<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    ctx: TaskContext<R>,
    target: PeerAddress,
    remote_peer_id: PeerId,
) -> Result<(), Error> {
    let effects = SyncContext::new(ctx, target, remote_peer_id);
    sync(effects).await
}

// The backward compatibility code has been removed since we are fully migrated to the unified SyncEffects trait

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    LoadLocalState(#[from] local_state::Error),
    #[error(transparent)]
    Membership(sync_membership::error::SyncMembership),
    #[error("unable to reach peer")]
    UnableToReachPeer,
    #[error(transparent)]
    SyncDocs(#[from] sync_docs::error::SyncDocs),
    #[error(transparent)]
    SyncDoc(#[from] sync_doc::error::SyncDocError),
    #[error("unable to get a session")]
    Session,
}

impl Error {
    fn unable_to_reach_peer() -> Self {
        Self::UnableToReachPeer
    }
}

pub(crate) enum MaybeSessionError {
    Expired,
    NotFound,
    Other(Error),
}

impl From<local_state::Error> for MaybeSessionError {
    fn from(err: local_state::Error) -> Self {
        MaybeSessionError::Other(Error::LoadLocalState(err))
    }
}

impl From<Error> for MaybeSessionError {
    fn from(err: Error) -> Self {
        MaybeSessionError::Other(err)
    }
}

impl From<sync_membership::error::SyncMembership> for MaybeSessionError {
    fn from(err: sync_membership::error::SyncMembership) -> Self {
        match err {
            sync_membership::error::SyncMembership::SessionExpired => MaybeSessionError::Expired,
            sync_membership::error::SyncMembership::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::Membership(other)),
        }
    }
}

impl From<sync_docs::error::SyncDocs> for MaybeSessionError {
    fn from(err: sync_docs::error::SyncDocs) -> Self {
        match err {
            sync_docs::error::SyncDocs::SessionExpired => MaybeSessionError::Expired,
            sync_docs::error::SyncDocs::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::SyncDocs(other)),
        }
    }
}

impl From<sync_doc::error::SyncDocError> for MaybeSessionError {
    fn from(err: sync_doc::error::SyncDocError) -> Self {
        match err {
            sync_doc::error::SyncDocError::SessionExpired => MaybeSessionError::Expired,
            sync_doc::error::SyncDocError::SessionNotFound => MaybeSessionError::NotFound,
            other => MaybeSessionError::Other(Error::SyncDoc(other)),
        }
    }
}
