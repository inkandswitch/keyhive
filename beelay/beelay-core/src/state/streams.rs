use std::{borrow::Cow, cell::RefCell, rc::Rc};

use futures::channel::oneshot;

use crate::{
    conn_info::ConnectionInfo,
    streams::{self, ConnRequestId, EstablishedStream, HandledMessage},
    PeerId, Request, Response, StreamDirection, StreamError, StreamId, UnixTimestamp,
    UnixTimestampMillis,
};

pub(crate) struct Streams<'a, R: rand::Rng + rand::CryptoRng> {
    pub(super) state: Cow<'a, Rc<RefCell<super::State<R>>>>,
}

impl<'a, R: rand::Rng + rand::CryptoRng> Streams<'a, R> {
    pub(crate) fn new(state: Cow<'a, Rc<RefCell<super::State<R>>>>) -> Self {
        Self { state }
    }

    pub(crate) fn new_stream(
        &mut self,
        now: UnixTimestamp,
        stream_direction: StreamDirection,
    ) -> StreamId {
        let stream_id = self
            .state
            .borrow_mut()
            .streams
            .new_stream(now, stream_direction.clone());
        stream_id
    }

    pub(crate) fn disconnect(&mut self, stream_id: StreamId) -> Result<(), StreamError> {
        self.state.borrow_mut().streams.remove(stream_id);
        Ok(())
    }

    pub(crate) fn established(&self) -> Vec<EstablishedStream> {
        self.state.borrow().streams.established().collect()
    }

    pub(crate) fn mark_sync_started(&mut self, now: UnixTimestampMillis, stream_id: StreamId) {
        self.state
            .borrow_mut()
            .streams
            .mark_sync_started(now, stream_id);
    }

    pub(crate) fn mark_sync_complete(&mut self, now: UnixTimestampMillis, stream_id: StreamId) {
        self.state
            .borrow_mut()
            .streams
            .mark_sync_complete(now, stream_id);
    }

    pub(crate) fn mark_received_sync_needed(&mut self, stream_id: StreamId) {
        self.state
            .borrow_mut()
            .streams
            .mark_received_sync_needed(stream_id);
    }

    pub(crate) fn clear_received_sync_needed(&mut self, stream_id: StreamId) {
        self.state
            .borrow_mut()
            .streams
            .clear_received_sync_needed(stream_id);
    }

    pub(crate) fn take_changed(&mut self) -> Vec<ConnectionInfo> {
        self.state.borrow_mut().streams.take_changed()
    }

    pub(crate) fn handle_message(
        &mut self,
        now: UnixTimestampMillis,
        stream_id: StreamId,
        msg: Vec<u8>,
    ) -> Result<Option<HandledMessage>, streams::error::StreamError> {
        let mut state = self.state.borrow_mut();
        state
            .streams
            .handle_stream_message(now.into(), stream_id, msg)
    }

    pub(crate) fn send_request(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        request: Request,
        reply: oneshot::Sender<Option<(PeerId, Response)>>,
    ) -> Result<ConnRequestId, StreamError> {
        self.state
            .borrow_mut()
            .streams
            .send_request(now, stream_id, request, reply)
    }

    pub(crate) fn send_response(
        &mut self,
        now: UnixTimestamp,
        stream_id: StreamId,
        req_id: ConnRequestId,
        resp: Response,
    ) -> Result<(), StreamError> {
        self.state
            .borrow_mut()
            .streams
            .send_response(now, stream_id, req_id, resp)
    }

    pub(crate) fn stop(&mut self) {
        self.state.borrow_mut().streams.stop()
    }

    pub(crate) fn finished(&self) -> bool {
        self.state.borrow().streams.finished()
    }
}
