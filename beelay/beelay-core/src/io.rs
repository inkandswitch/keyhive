use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use futures::channel::{mpsc, oneshot};

use crate::{
    doc_status::DocEvent, driver, network, serialization::hex, streams::IncomingStreamEvent,
    task_context::JobFuture, DocumentId, EndpointId, NewRequest, StorageKey,
};

#[derive(Clone)]
pub(crate) enum IoHandle {
    Driver(crate::driver::TinCans),
    Loading(mpsc::UnboundedSender<driver::DriverEvent>),
}

impl IoHandle {
    pub(crate) fn new_driver(driver: crate::driver::TinCans) -> Self {
        Self::Driver(driver)
    }

    pub(crate) fn new_loading(tx: mpsc::UnboundedSender<driver::DriverEvent>) -> Self {
        Self::Loading(tx)
    }

    /// Request a new storage task be executed, the result to be sent to `reply`
    pub(crate) fn new_task(&self, task: IoTask, reply: oneshot::Sender<IoResult>) {
        match self {
            Self::Driver(d) => d.new_task(task, reply),
            Self::Loading(tx) => {
                let _ = tx.unbounded_send(driver::DriverEvent::Task { task, reply });
            }
        }
    }

    /// Request a new request be made to `endpoint_id`, the result to be sent to `reply`
    pub(crate) fn new_endpoint_request(
        &self,
        endpoint_id: EndpointId,
        request: NewRequest,
        reply: oneshot::Sender<network::InnerRpcResponse>,
    ) {
        match self {
            Self::Driver(d) => d.new_endpoint_request(endpoint_id, request, reply),
            Self::Loading(_ctx) => {}
        }
    }

    /// Emit a new document event
    pub(crate) fn new_doc_event(&self, doc_id: DocumentId, event: DocEvent) {
        match self {
            Self::Driver(d) => d.new_doc_event(doc_id, event),
            Self::Loading(_) => {}
        }
    }

    /// Send a new event to be handled by the stream processing subsystem (streams::run_streams)
    pub(crate) fn new_inbound_stream_event(&self, event: IncomingStreamEvent) {
        match self {
            Self::Driver(d) => d.new_inbound_stream_event(event),
            Self::Loading(_) => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IoTaskId(u64);

static LAST_IO_TASK_ID: AtomicU64 = AtomicU64::new(0);

impl IoTaskId {
    pub(crate) fn new() -> IoTaskId {
        IoTaskId(LAST_IO_TASK_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> String {
        self.0.to_string()
    }
}

impl std::str::FromStr for IoTaskId {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

#[derive(Debug)]
pub struct IoTask {
    id: IoTaskId,
    action: IoAction,
}

impl IoTask {
    pub(crate) fn load(key: StorageKey) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::Load { key },
        }
    }

    pub(crate) fn load_range(prefix: StorageKey) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::LoadRange { prefix },
        }
    }

    pub(crate) fn list_one_level(prefix: StorageKey) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::ListOneLevel { prefix },
        }
    }

    pub(crate) fn put(key: StorageKey, data: Vec<u8>) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::Put { key, data },
        }
    }

    pub(crate) fn delete(key: StorageKey) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::Delete { key },
        }
    }

    pub(crate) fn sign(payload: Vec<u8>) -> IoTask {
        IoTask {
            id: IoTaskId::new(),
            action: IoAction::Sign { payload },
        }
    }

    pub fn action(&self) -> &IoAction {
        &self.action
    }

    pub fn take_action(self) -> IoAction {
        self.action
    }

    pub fn id(&self) -> IoTaskId {
        self.id
    }
}

#[derive(Debug)]
pub enum IoAction {
    Load { key: StorageKey },
    LoadRange { prefix: StorageKey },
    ListOneLevel { prefix: StorageKey },
    Put { key: StorageKey, data: Vec<u8> },
    Delete { key: StorageKey },
    Sign { payload: Vec<u8> },
}

pub struct IoResult {
    id: IoTaskId,
    payload: IoResultPayload,
}

impl std::fmt::Debug for IoResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let payload_desc = match &self.payload {
            IoResultPayload::Load(payload) => format!(
                "Load({})",
                payload
                    .as_ref()
                    .map(|b| format!("{} bytes", b.len()))
                    .unwrap_or_else(|| "None".to_string())
            ),
            IoResultPayload::LoadRange(payload) => format!("LoadRange({} keys)", payload.len()),
            IoResultPayload::ListOneLevel(result) => format!("ListOneLevel({} keys)", result.len()),
            IoResultPayload::Put => "Put".to_string(),
            IoResultPayload::Delete => "Delete".to_string(),
            IoResultPayload::Sign(_) => "Sign".to_string(),
        };
        f.debug_struct("IoResult")
            .field("id", &self.id)
            .field("payload", &payload_desc)
            .finish()
    }
}

impl IoResult {
    pub fn load(id: IoTaskId, payload: Option<Vec<u8>>) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Load(payload),
        }
    }

    pub fn load_range(id: IoTaskId, payload: HashMap<StorageKey, Vec<u8>>) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::LoadRange(payload),
        }
    }

    pub fn list_one_level(id: IoTaskId, payload: Vec<StorageKey>) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::ListOneLevel(payload),
        }
    }

    pub fn put(id: IoTaskId) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Put,
        }
    }

    pub fn delete(id: IoTaskId) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Delete,
        }
    }

    pub fn sign(id: IoTaskId, signature: ed25519_dalek::Signature) -> IoResult {
        IoResult {
            id,
            payload: IoResultPayload::Sign(signature),
        }
    }

    pub(crate) fn take_payload(self) -> IoResultPayload {
        self.payload
    }

    #[allow(dead_code)]
    pub(crate) fn payload(&self) -> &IoResultPayload {
        &self.payload
    }

    pub fn id(&self) -> IoTaskId {
        self.id
    }
}

pub(crate) enum IoResultPayload {
    Load(Option<Vec<u8>>),
    LoadRange(HashMap<StorageKey, Vec<u8>>),
    ListOneLevel(Vec<StorageKey>),
    Put,
    Delete,
    Sign(ed25519_dalek::Signature),
}

#[derive(Clone)]
pub(crate) struct Signer {
    verifying_key: ed25519_dalek::VerifyingKey,
    io: IoHandle,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer({})", hex::encode(self.verifying_key.as_bytes()))
    }
}

impl Signer {
    pub(crate) fn new(verifying_key: ed25519_dalek::VerifyingKey, io: IoHandle) -> Self {
        Self { verifying_key, io }
    }
}

impl keyhive_core::crypto::verifiable::Verifiable for Signer {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key
    }
}

impl keyhive_core::crypto::signer::async_signer::AsyncSigner for Signer {
    async fn try_sign_bytes_async(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, keyhive_core::crypto::signed::SigningError> {
        let (tx_reply, rx_reply) = oneshot::channel();
        self.io
            .new_task(IoTask::sign(payload_bytes.to_vec()), tx_reply);
        match JobFuture(rx_reply).await.take_payload() {
            IoResultPayload::Sign(s) => Ok(s),
            _ => panic!("unexpected task result"),
        }
    }
}
