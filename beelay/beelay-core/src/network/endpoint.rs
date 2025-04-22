use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    auth::{self, offset_seconds::OffsetSeconds},
    serialization::Encode,
    Audience, PeerId, Request, Response, UnixTimestamp,
};

mod endpoint_request;
pub use endpoint_request::EndpointRequest;
mod endpoint_response;
pub use endpoint_response::EndpointResponse;
use futures::channel::{mpsc, oneshot};

use super::OutboundRequestId;

pub(crate) struct Endpoints {
    endpoints: HashMap<EndpointId, Endpoint>,
    // The other end of this channel is polled by the driver and used to send outgoing
    // endpoint requests
    outbox: mpsc::UnboundedSender<(EndpointId, OutboundRequestId, auth::Message)>,
    pending_requests: HashMap<OutboundRequestId, oneshot::Sender<Option<(PeerId, Response)>>>,
}

impl Endpoints {
    pub(crate) fn new(
        outbox: mpsc::UnboundedSender<(EndpointId, OutboundRequestId, auth::Message)>,
    ) -> Self {
        Self {
            endpoints: HashMap::new(),
            pending_requests: HashMap::new(),
            outbox,
        }
    }

    pub(crate) fn register_endpoint(&mut self, audience: Audience) -> EndpointId {
        let id = EndpointId::new();
        self.endpoints.insert(id, Endpoint { audience });
        id
    }

    pub(crate) fn unregister_endpoint(&mut self, endpoint_id: EndpointId) {
        self.endpoints.remove(&endpoint_id);
    }

    pub(crate) fn send_request(
        &mut self,
        now: UnixTimestamp,
        endpoint_id: EndpointId,
        request_id: OutboundRequestId,
        request: Request,
        reply: oneshot::Sender<Option<(PeerId, Response)>>,
    ) -> Result<(), NoSuchEndpoint> {
        let Some(endpoint) = self.endpoints.get(&endpoint_id) else {
            return Err(NoSuchEndpoint);
        };
        let msg = auth::send(now, OffsetSeconds(0), endpoint.audience, request.encode());
        self.pending_requests.insert(request_id, reply);
        let _ = self.outbox.unbounded_send((endpoint_id, request_id, msg));
        Ok(())
    }

    pub(crate) fn handle_response(
        &mut self,
        now: UnixTimestamp,
        our_peer_id: &PeerId,
        req_id: OutboundRequestId,
        response: auth::Signed<auth::Message>,
    ) {
        match auth::receive::<Response>(now, response, our_peer_id, None) {
            Ok(authenticated) => {
                if let Some(reply) = self.pending_requests.remove(&req_id) {
                    let _ = reply.send(Some((authenticated.from.into(), authenticated.content)));
                }
            }
            Err(e) => {
                tracing::warn!(err=?e, "failed to authenticate response");
                if let Some(reply) = self.pending_requests.remove(&req_id) {
                    let _ = reply.send(None);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointId(u64);

static LAST_ENDPOINT_ID: AtomicU64 = AtomicU64::new(0);

impl EndpointId {
    fn new() -> Self {
        Self(LAST_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

pub struct Endpoint {
    // id: EndpointId,
    audience: Audience,
}

#[derive(Debug, thiserror::Error)]
#[error("no such endpoint")]
pub struct NoSuchEndpoint;
