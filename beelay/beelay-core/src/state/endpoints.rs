use std::{borrow::Cow, cell::RefCell, rc::Rc};

use futures::channel::oneshot;

use crate::{
    auth,
    network::endpoint::{self, NoSuchEndpoint},
    Audience, EndpointId, OutboundRequestId, PeerId, Request, Response, UnixTimestamp,
};

pub(crate) struct Endpoints<'a, R: rand::Rng + rand::CryptoRng>(
    Cow<'a, Rc<RefCell<super::State<R>>>>,
);

impl<'a, R: rand::Rng + rand::CryptoRng> Endpoints<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Endpoints(state)
    }

    pub(crate) fn register_endpoint(&self, audience: Audience) -> endpoint::EndpointId {
        let mut state = RefCell::borrow_mut(&self.0);
        state.endpoints.register_endpoint(audience)
    }

    pub(crate) fn unregister_endpoint(&self, endpoint_id: endpoint::EndpointId) {
        let mut state = RefCell::borrow_mut(&self.0);
        state.endpoints.unregister_endpoint(endpoint_id);
    }

    pub(crate) fn send_request(
        &self,
        now: UnixTimestamp,
        endpoint_id: EndpointId,
        request_id: OutboundRequestId,
        request: Request,
        reply: oneshot::Sender<Option<(PeerId, Response)>>,
    ) -> Result<(), NoSuchEndpoint> {
        self.0
            .borrow_mut()
            .endpoints
            .send_request(now, endpoint_id, request_id, request, reply)
    }

    pub(crate) fn handle_response(
        &self,
        now: UnixTimestamp,
        req_id: OutboundRequestId,
        response: auth::Signed<auth::Message>,
    ) {
        let mut state = RefCell::borrow_mut(&self.0);
        let our_peer_id = state.our_peer_id;
        state
            .endpoints
            .handle_response(now, &our_peer_id, req_id, response);
    }
}
