use std::{borrow::Cow, cell::RefCell, rc::Rc};

use crate::{network::endpoint, Audience};

pub(crate) struct Endpoints<'a, R: rand::Rng + rand::CryptoRng>(
    Cow<'a, Rc<RefCell<super::State<R>>>>,
);

impl<'a, R: rand::Rng + rand::CryptoRng> Endpoints<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Endpoints(state)
    }

    pub(crate) fn audience_of(&self, endpoint_id: endpoint::EndpointId) -> Option<crate::Audience> {
        let state = RefCell::borrow(&self.0);
        state.endpoints.audience_of(endpoint_id)
    }

    pub(crate) fn register_endpoint(&self, audience: Audience) -> endpoint::EndpointId {
        let mut state = RefCell::borrow_mut(&self.0);
        state.endpoints.register_endpoint(audience)
    }

    pub(crate) fn unregister_endpoint(&self, endpoint_id: endpoint::EndpointId) {
        let mut state = RefCell::borrow_mut(&self.0);
        state.endpoints.unregister_endpoint(endpoint_id);
    }
}
