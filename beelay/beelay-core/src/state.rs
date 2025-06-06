use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
    time::Duration,
};

use futures::channel::mpsc;
use keyhive::KeyhiveCtx;
use keyhive_core::{
    crypto::verifiable::Verifiable, keyhive::Keyhive,
    store::ciphertext::memory::MemoryCiphertextStore,
};

mod docs;
pub(crate) use docs::{DocUpdateBuilder, Docs};
mod endpoints;
pub(crate) use endpoints::Endpoints;
pub(crate) mod keyhive;
mod sessions;
pub(crate) use sessions::Sessions;
mod streams;
pub(crate) use streams::Streams;

use crate::{
    auth, doc_state::DocState, io::Signer, network::endpoint, streams::UnsignedStreamEvent, sync,
    CommitHash, DocumentId, EndpointId, OutboundRequestId, PeerId, StreamId,
};

pub(crate) struct State<R: rand::Rng + rand::CryptoRng> {
    signer: Signer,
    docs: HashMap<DocumentId, DocState>,
    docs_with_changes: HashSet<DocumentId>,
    keyhive: Rc<futures::lock::Mutex<Beehive<R>>>,
    streams: crate::streams::Streams,
    endpoints: endpoint::Endpoints,
    rng: Rc<RefCell<R>>,
    sync_sessions: sync::Sessions,
    our_peer_id: PeerId,
}

/// The Beelay-visible Keyhive
type Beehive<R> = Keyhive<
    Signer,
    CommitHash,
    Vec<u8>,
    MemoryCiphertextStore<CommitHash, Vec<u8>>,
    crate::keyhive::Listener,
    R,
>;

impl<R: rand::Rng + rand::CryptoRng> State<R> {
    pub(crate) fn new(
        rng: R,
        signer: Signer,
        keyhive: Beehive<R>,
        docs: HashMap<DocumentId, DocState>,
        session_duration: Duration,
        tx_outbound_stream_msgs: mpsc::UnboundedSender<(StreamId, UnsignedStreamEvent)>,
        tx_outbound_endpoint_msgs: mpsc::UnboundedSender<(
            EndpointId,
            OutboundRequestId,
            auth::Message,
        )>,
    ) -> Self {
        let our_peer_id = keyhive.active().borrow().verifying_key().into();
        let verifying_key = signer.verifying_key();
        Self {
            signer,
            our_peer_id,
            docs,
            docs_with_changes: HashSet::new(),
            keyhive: Rc::new(futures::lock::Mutex::new(keyhive)),
            streams: crate::streams::Streams::new(tx_outbound_stream_msgs, verifying_key),
            endpoints: endpoint::Endpoints::new(tx_outbound_endpoint_msgs),
            rng: Rc::new(RefCell::new(rng)),
            sync_sessions: sync::Sessions::new(session_duration),
        }
    }

    pub(crate) fn signer(&self) -> Signer {
        self.signer.clone()
    }
}

pub(crate) struct StateAccessor<'a, R: rand::Rng + rand::CryptoRng>(Cow<'a, Rc<RefCell<State<R>>>>);

impl<'a, R: rand::Rng + rand::CryptoRng> StateAccessor<'a, R> {
    pub(crate) fn new(state: &'a Rc<RefCell<State<R>>>) -> Self {
        Self(Cow::Borrowed(state))
    }

    pub(crate) fn to_owned(&self) -> StateAccessor<'static, R> {
        StateAccessor(Cow::Owned(Rc::clone(&self.0)))
    }

    pub(crate) fn docs(&self) -> Docs<'a, R> {
        Docs::new(self.0.clone())
    }

    pub(crate) fn keyhive(&self) -> KeyhiveCtx<'a, R> {
        KeyhiveCtx::new(self.0.clone())
    }

    pub(crate) fn streams(&self) -> Streams<'a, R> {
        Streams::new(self.0.clone())
    }

    pub(crate) fn endpoints(&self) -> Endpoints<'a, R> {
        Endpoints::new(self.0.clone())
    }

    pub(crate) fn our_peer_id(&self) -> PeerId {
        self.0.borrow().our_peer_id
    }
}

impl<'a, R: rand::Rng + rand::CryptoRng + Clone + 'static> StateAccessor<'a, R> {
    pub(crate) fn sessions(&self) -> Sessions<'a, R> {
        Sessions::new(self.0.clone())
    }
}
