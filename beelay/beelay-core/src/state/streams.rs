use std::{cell::RefCell, rc::Rc};

use crate::{Forwarding, PeerId, StreamDirection, StreamError, StreamId};

pub(crate) struct Streams<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: &'a Rc<RefCell<super::State<R>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Streams<'a, R> {
    pub(crate) fn new_stream(
        &mut self,
        stream_direction: StreamDirection,
        forwarding: Forwarding,
    ) -> StreamId {
        self.state
            .borrow_mut()
            .streams
            .new_stream(stream_direction, forwarding)
    }

    pub(crate) fn receive_message(
        &mut self,
        stream_id: StreamId,
        message: Vec<u8>,
    ) -> Result<(), StreamError> {
        self.state
            .borrow_mut()
            .streams
            .send_message(stream_id, message)
    }

    pub(crate) fn disconnect(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.state.borrow_mut().streams.disconnect(stream_id)
    }

    pub(crate) fn mark_handshake_complete(&self, stream_id: StreamId, their_peer_id: PeerId) {
        self.state
            .borrow_mut()
            .streams
            .mark_handshake_complete(stream_id, their_peer_id);
    }
}
