use std::{borrow::Cow, cell::RefCell, collections::HashSet, rc::Rc};

use crate::{streams::CompletedHandshake, StreamDirection, StreamError, StreamId};

pub(crate) struct Streams<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Streams<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    pub(crate) fn new_stream(&mut self, stream_direction: StreamDirection) -> StreamId {
        let stream_id = self
            .state
            .borrow_mut()
            .streams
            .new_stream(stream_direction.clone());
        stream_id
    }

    pub(crate) fn disconnect(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.state.borrow_mut().streams.remove(stream_id);
        Ok(())
    }

    pub(crate) fn mark_handshake_complete(
        &self,
        stream_id: StreamId,
        handshake: CompletedHandshake,
    ) {
        self.state
            .borrow_mut()
            .streams
            .mark_handshake_complete(stream_id, handshake);
    }

    pub(crate) fn established(&self) -> HashSet<(StreamId, CompletedHandshake)> {
        self.state.borrow().streams.established().collect()
    }
}
