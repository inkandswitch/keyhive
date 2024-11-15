use std::{collections::HashMap, future::Future};

use crate::{
    auth,
    io::{IoResult, IoResultPayload, IoTask},
    network::InnerRpcResponse,
    DocEvent, EventResults, IoTaskId, OutboundRequestId, SignedMessage, StorageKey,
};

use futures::{channel::oneshot, FutureExt};

pub enum JobComplete {
    Io(IoResult),
    Request(OutboundRequestId, InnerRpcResponse),
}

pub(crate) struct Jobs {
    load_range: HashMap<IoTaskId, oneshot::Sender<HashMap<StorageKey, Vec<u8>>>>,
    load: HashMap<IoTaskId, oneshot::Sender<Option<Vec<u8>>>>,
    put: HashMap<IoTaskId, oneshot::Sender<()>>,
    delete: HashMap<IoTaskId, oneshot::Sender<()>>,
    requests: HashMap<OutboundRequestId, oneshot::Sender<InnerRpcResponse>>,
}

impl Jobs {
    pub(crate) fn new() -> Self {
        Self {
            load_range: HashMap::new(),
            load: HashMap::new(),
            put: HashMap::new(),
            delete: HashMap::new(),
            requests: HashMap::new(),
        }
    }

    pub(super) fn job_complete(&mut self, job_result: JobComplete) {
        match job_result {
            JobComplete::Io(io_result) => {
                let io_task_id = io_result.id();
                match io_result.take_payload() {
                    IoResultPayload::Load(result) => {
                        self.load.remove(&io_task_id).map(|r| r.send(result));
                    }
                    IoResultPayload::LoadRange(result) => {
                        self.load_range.remove(&io_task_id).map(|r| r.send(result));
                    }
                    IoResultPayload::Put => {
                        self.put.remove(&io_task_id).map(|r| r.send(()));
                    }
                    IoResultPayload::Delete => {
                        self.delete.remove(&io_task_id).map(|r| r.send(()));
                    }
                }
            }
            JobComplete::Request(req_id, response) => {
                self.requests.remove(&req_id).map(|r| r.send(response));
            }
        }
    }

    pub(crate) fn load(
        &mut self,
        results: &mut EventResults,
        key: StorageKey,
    ) -> JobFuture<Option<Vec<u8>>> {
        let io_task_id = IoTaskId::new();
        let (tx, rx) = oneshot::channel();
        self.load.insert(io_task_id, tx);
        results.new_tasks.push(IoTask::load(io_task_id, key));
        JobFuture(rx)
    }

    pub(crate) fn load_range(
        &mut self,
        results: &mut EventResults,
        prefix: StorageKey,
    ) -> JobFuture<HashMap<StorageKey, Vec<u8>>> {
        let io_task_id = IoTaskId::new();
        let (tx, rx) = oneshot::channel();
        self.load_range.insert(io_task_id, tx);
        results
            .new_tasks
            .push(IoTask::load_range(io_task_id, prefix));
        JobFuture(rx)
    }

    pub(crate) fn put(
        &mut self,
        results: &mut EventResults,
        key: StorageKey,
        value: Vec<u8>,
    ) -> JobFuture<()> {
        let io_task_id = IoTaskId::new();
        let (tx, rx) = oneshot::channel();
        self.put.insert(io_task_id, tx);
        results.new_tasks.push(IoTask::put(io_task_id, key, value));
        JobFuture(rx)
    }

    pub(crate) fn delete(&mut self, results: &mut EventResults, key: StorageKey) -> JobFuture<()> {
        let io_task_id = IoTaskId::new();
        let (tx, rx) = oneshot::channel();
        self.delete.insert(io_task_id, tx);
        results.new_tasks.push(IoTask::delete(io_task_id, key));
        JobFuture(rx)
    }

    pub(crate) fn request(
        &mut self,
        results: &mut EventResults,
        endpoint: crate::EndpointId,
        request: auth::Signed<auth::Message>,
    ) -> JobFuture<InnerRpcResponse> {
        let req_id = OutboundRequestId::new();
        let (tx, rx) = oneshot::channel();
        self.requests.insert(req_id, tx);
        results
            .new_requests
            .entry(endpoint)
            .or_default()
            .push(crate::NewRequest {
                id: req_id,
                request: SignedMessage(request),
            });
        JobFuture(rx)
    }

    pub(crate) fn emit_doc_event(&mut self, results: &mut EventResults, event: DocEvent) {
        results.notifications.push(event);
    }
}

pub(crate) struct JobFuture<T>(pub(crate) oneshot::Receiver<T>);

impl<T> Future for JobFuture<T> {
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.0.poll_unpin(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(result),
            std::task::Poll::Ready(Err(_)) => {
                tracing::debug!(
                    "polling a cancelled JobFuture, the whole task should be dropped shortly"
                );
                std::task::Poll::Pending
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
