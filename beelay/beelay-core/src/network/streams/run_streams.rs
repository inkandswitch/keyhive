use std::collections::HashMap;

use futures::{
    channel::{mpsc, oneshot},
    stream::FuturesUnordered,
    FutureExt, SinkExt, StreamExt,
};

use super::connection::{self, ConnRequestId};
use crate::{OutboundRequestId, Request};

use super::{InnerRpcResponse, StreamDirection, StreamError, StreamEvent, StreamId, TaskContext};

struct RunningStreamHandle {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    outbound_requests: mpsc::UnboundedSender<(
        OutboundRequestId,
        Request,
        oneshot::Sender<Option<Result<InnerRpcResponse, StreamError>>>,
    )>,
    disconnect: oneshot::Sender<()>,
}

pub(crate) enum IncomingStreamEvent {
    Create(StreamId, StreamDirection),
    Disconnect(StreamId),
    Message(StreamId, Vec<u8>),
    SendRequest(super::SendRequest),
}

pub(crate) fn run_streams<
    R: rand::Rng + rand::CryptoRng + 'static,
    Str: futures::Stream<Item = IncomingStreamEvent> + Unpin + 'static,
>(
    ctx: TaskContext<R>,
    incoming: Str,
) -> impl futures::Stream<Item = (StreamId, StreamEvent)> {
    let running_streams = futures::stream::SelectAll::new();
    let stream_handles = HashMap::new();
    let incoming = incoming.fuse();

    struct Running<R: rand::Rng + rand::CryptoRng, F, Str> {
        running_streams: futures::stream::SelectAll<F>,
        stream_handles: HashMap<StreamId, RunningStreamHandle>,
        incoming: Str,
        ctx: TaskContext<R>,
        stopping: bool,
    }

    let running = Running {
        running_streams,
        stream_handles,
        incoming,
        ctx,
        stopping: false,
    };

    futures::stream::unfold(running, move |mut running| async move {
        let mut stopping = running.ctx.stopping().fuse();
        loop {
            if running.stopping {
                tracing::trace!(
                    num_handles = running.stream_handles.len(),
                    "checking if we can stop in run_streams"
                );
                if running.stream_handles.is_empty() {
                    return None;
                }
            }
            futures::select! {
                _ = stopping => {
                    running.stopping = true;
                    continue;
                }
                next_evt = running.incoming.next() => {
                    let Some(next_evt) = next_evt else {
                        return None;
                    };
                    match next_evt {
                        IncomingStreamEvent::Create(stream_id, stream_direction) => {
                            if running.stopping {
                                tracing::warn!(?stream_id, "stream created while stopping");
                                continue;
                            }
                            let (tx, rx) = mpsc::unbounded();
                            let (tx_requests, rx_requests) = mpsc::unbounded();
                            let (tx_disconnect, rx_disconnect) = oneshot::channel();
                            let handle = RunningStreamHandle {
                                tx,
                                outbound_requests: tx_requests,
                                disconnect: tx_disconnect,
                            };
                            let handler = {
                                let stream_id = stream_id.clone();
                                let stream = StreamToRun {
                                    ctx: running.ctx.clone(),
                                    direction: stream_direction,
                                    stream_id,
                                    incoming: rx,
                                    outbound_requests: rx_requests,
                                    disconnect: rx_disconnect,
                                };
                                stream.run().map(move |evt| (stream_id, evt))
                            };
                            running.running_streams.push(handler);
                            running.stream_handles.insert(stream_id, handle);
                            continue;
                        }
                        IncomingStreamEvent::Disconnect(stream_id) => {
                            let Some(running_handle) = running.stream_handles.remove(&stream_id) else {
                                tracing::warn!(?stream_id, "disconnect event for unknown stream");
                                continue;
                            };
                            running_handle.disconnect.send(());
                            continue;
                        }
                        IncomingStreamEvent::Message(stream_id, vec) => {
                            let Some(running_handle) = running.stream_handles.get_mut(&stream_id) else {
                                tracing::warn!(?stream_id, "receive message for unknown stream");
                                continue;
                            };
                            running_handle.tx.unbounded_send(vec);
                            continue;
                        }
                        IncomingStreamEvent::SendRequest(super::SendRequest{stream_id, req_id, request, reply}) => {
                            let Some(running_handle) = running.stream_handles.get_mut(&stream_id) else {
                                tracing::warn!(?stream_id, "send request for unknown stream");
                                if let Err(e) = reply.send(Some(Err(StreamError::NoSuchStream))) {
                                    tracing::warn!(err=?e, "unable to send error back to sendrequest");
                                };
                                continue;
                            };
                            running_handle.outbound_requests.unbounded_send((req_id, request, reply));
                            continue;
                        }
                    }
                }
                outgoing = running.running_streams.select_next_some() => {
                    let (stream_id, event) = outgoing;
                    if let StreamEvent::Close = event {
                        running.stream_handles.remove(&stream_id);
                    }
                    return Some(((stream_id, event), running))
                }
            }
        }
    })
}

struct StreamToRun<R: rand::Rng + rand::CryptoRng> {
    ctx: TaskContext<R>,
    direction: crate::StreamDirection,
    stream_id: StreamId,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    outbound_requests: mpsc::UnboundedReceiver<(
        OutboundRequestId,
        Request,
        oneshot::Sender<Option<Result<InnerRpcResponse, StreamError>>>,
    )>,
    disconnect: oneshot::Receiver<()>,
}

impl<R: rand::Rng + rand::CryptoRng + 'static> StreamToRun<R> {
    fn run(self) -> impl futures::Stream<Item = StreamEvent> {
        let Self {
            ctx,
            direction,
            stream_id,
            mut incoming,
            mut outbound_requests,
            mut disconnect,
        } = self;
        let (mut out_tx, out_rx) = mpsc::unbounded();

        let processing = async move {
            // First, run the handshake
            let mut handshake_step = match direction {
                StreamDirection::Connecting { remote_audience } => {
                    connection::Handshake::connect(&ctx, remote_audience)
                }
                StreamDirection::Accepting { receive_audience } => {
                    connection::Handshake::accept(receive_audience)
                }
            };

            let mut stopping = false;

            tracing::debug!("beginning handshake");
            let mut connection = loop {
                if let Some(msg) = handshake_step.next_msg.take() {
                    tracing::trace!(?msg, "sending handshake message");
                    if let Err(e) = out_tx.send(StreamEvent::Send(msg)).await {
                        tracing::debug!(?e, "stream closed in handshake");
                        return;
                    }
                }
                match handshake_step.state {
                    connection::Connecting::Complete(c) => break c,
                    connection::Connecting::Handshaking(h) => {
                        let received = futures::select! {
                            msg = incoming.next() => {
                                let Some(received) = msg else {
                                    tracing::debug!("stream closed before handshake completed");
                                    return;
                                };
                                received
                            },
                            _ = disconnect => {
                                tracing::debug!("stream closed before handshake completed");
                                return;
                            }
                            _ = ctx.stopping().fuse() => {
                                tracing::debug!("beelay stopping in handshake");
                                return;
                            }
                        };
                        tracing::trace!(?received, "received message in handshake");
                        match h.receive_message(&ctx, received) {
                            Ok(next_step) => handshake_step = next_step,
                            Err(e) => {
                                tracing::debug!(?e, "closing stream as it failed to connect");
                                return;
                            }
                        }
                    }
                    connection::Connecting::Failed(f) => {
                        tracing::debug!(?f, "closing stream as it failed to connect");
                        return;
                    }
                }
            };

            if let Err(_) = out_tx
                .send(StreamEvent::HandshakeComplete {
                    their_peer_id: connection.their_peer_id(),
                })
                .await
            {
                tracing::debug!("error sending handshake complet");
            }

            // Now process incoming messages

            let mut running_inbound_requests = FuturesUnordered::new();
            let mut running_outbound_requests = HashMap::<
                ConnRequestId,
                (
                    OutboundRequestId,
                    oneshot::Sender<Option<Result<InnerRpcResponse, StreamError>>>,
                ),
            >::new();

            let mut stopped = ctx.stopping().fuse();
            loop {
                if stopping {
                    tracing::trace!(
                        num_inbound = running_inbound_requests.len(),
                        num_outbound = running_outbound_requests.len(),
                        "checking if we can stop this stream"
                    );
                    if running_inbound_requests.is_empty() && running_outbound_requests.is_empty() {
                        return;
                    }
                }
                futures::select! {
                    _ = stopped => {
                        for (_, (_, reply)) in running_outbound_requests.drain() {
                            let _ = reply.send(Some(Err(StreamError::StreamClosed)));
                        }
                        stopping = true;
                    }
                    received = incoming.next().fuse() => {
                        let Some(received) = received else {
                            tracing::debug!("connection closed");
                            return;
                        };
                        match connection.receive_message(received) {
                            Ok(msg) => match msg {
                                connection::ConnectionMessage::Request { id, msg } => {
                                    if stopping {
                                        tracing::debug!("stopping, not processing request");
                                        continue;
                                    }
                                    let req_ctx = ctx.clone();
                                    let fut = async move {
                                        let resp = crate::request_handlers::handle_request(
                                            req_ctx,
                                            *msg,
                                            None,
                                        ).await;
                                        (id, resp)
                                    };
                                    running_inbound_requests.push(fut);
                                }
                                connection::ConnectionMessage::Response { id, msg } => {
                                    let Some((_req_id, reply)) = running_outbound_requests.remove(&id) else {
                                        tracing::warn!(conn_req_id=?id, "received response for unknown request, closing stream");
                                        return;
                                    };
                                    let _ = reply.send(Some(Ok(msg)));
                                }
                            },
                            Err(e) => {
                                tracing::debug!(?e, "closing stream as it failed to connect");
                                return;
                            }
                        }
                    }
                    new_outbound = outbound_requests.next().fuse() => {
                        let Some((req_id, req, reply)) = new_outbound else {
                            tracing::debug!("outbound requests stream closed");
                            return;
                        };
                        if stopping {
                            tracing::debug!("stopping, not processing outbound request");
                            let _ = reply.send(None);
                            continue
                        }
                        tracing::debug!(?req, remote_peer=%connection.their_peer_id(), "sending outbound request");
                        let signed = ctx.auth().sign_message(
                            crate::Audience::peer(&connection.their_peer_id()),
                            req,
                        );
                        let (conn_req_id, msg) = connection.encode_request(signed);
                        if let Err(e) = out_tx.unbounded_send(StreamEvent::Send(msg)) {
                            tracing::debug!(?e, "stream closed in outbound request");
                            return;
                        }
                        running_outbound_requests.insert(conn_req_id, (req_id, reply));
                    }
                    completed_inbound = running_inbound_requests.next() => {
                        let Some((conn_id, resp)) = completed_inbound else {
                            continue;
                        };
                        let response = match resp {
                            Ok(r) => {
                                let signed = ctx.auth().sign_message(
                                    crate::Audience::peer(&connection.their_peer_id()),
                                    r.response,
                                );
                                InnerRpcResponse::Response(Box::new(signed))
                            },
                            Err(_) => InnerRpcResponse::AuthFailed,
                        };
                        let msg = connection.encode_response(conn_id, response);
                        if let Err(_) = out_tx.unbounded_send(StreamEvent::Send(msg)) {
                            tracing::debug!("stream closed in response");
                            return;
                        }
                    },
                    _ = disconnect => {
                        tracing::debug!("stream disconnected by us");
                        for (_, reply) in running_outbound_requests.into_values() {
                            let _ = reply.send(None);
                        }
                        return
                    }
                }
            }
        };

        futures::stream::select(
            out_rx,
            futures::stream::once(Box::pin(async move {
                processing.await;
                StreamEvent::Close
            })),
        )
    }
}
