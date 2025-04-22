use std::{cell::RefCell, collections::HashMap, future::Future, rc::Rc, time::Duration};

use ed25519_dalek::VerifyingKey;
use futures::{
    channel::{mpsc, oneshot},
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use keyhive_core::crypto::verifiable::Verifiable;

mod executor;

use crate::{
    auth, commands,
    conn_info::ConnectionInfo,
    doc_status::DocEvent,
    io::{IoHandle, IoResult, IoTask},
    keyhive_storage, loading,
    network::EndpointRequest,
    request_handlers,
    serialization::Encode,
    state::State,
    streams::{self, HandledMessage, UnsignedStreamEvent},
    sync_loops, Command, CommandId, CommandResult, DocumentId, EndpointId, EventResults, IoTaskId,
    NewRequest, OutboundRequestId, PeerId, Signer, StorageKey, StreamEvent, StreamId, TaskContext,
    UnixTimestampMillis,
};

pub struct SpawnArgs<R> {
    pub(crate) now: Rc<RefCell<UnixTimestampMillis>>,
    pub(crate) rng: R,
    pub(crate) rx_input: mpsc::UnboundedReceiver<DriverInput>,
    pub(crate) tx_output: mpsc::UnboundedSender<DriverOutput>,
}

pub(crate) struct Driver {
    now: Rc<RefCell<UnixTimestampMillis>>,
    io_tasks: HashMap<IoTaskId, oneshot::Sender<IoResult>>,
    rx_output: mpsc::UnboundedReceiver<DriverOutput>,
    tx_input: mpsc::UnboundedSender<DriverInput>,
    executor: executor::LocalExecutor,
}

impl Driver {
    pub(crate) fn start<R, F, Fut>(rng: R, now: UnixTimestampMillis, f: F) -> Self
    where
        F: FnOnce(SpawnArgs<R>) -> Fut,
        Fut: Future<Output = ()> + 'static,
    {
        let (tx_driver_events, rx_driver_events) = mpsc::unbounded();
        let (tx_input, rx_input) = mpsc::unbounded();
        let now = Rc::new(RefCell::new(now));

        let spawn_args = SpawnArgs {
            now: now.clone(),
            rng,
            rx_input,
            tx_output: tx_driver_events,
        };
        let fut = f(spawn_args);
        let executor = executor::LocalExecutor::spawn(fut);

        Self {
            now,
            io_tasks: HashMap::new(),
            rx_output: rx_driver_events,
            tx_input,
            executor,
        }
    }

    pub(crate) fn handle_io_complete(&mut self, io_result: IoResult) {
        let Some(reply) = self.io_tasks.remove(&io_result.id()) else {
            tracing::warn!("received IO completion for unknown task");
            return;
        };
        let _ = reply.send(io_result);
    }

    pub(crate) fn handle_stream_message(&mut self, stream_id: StreamId, msg: Vec<u8>) {
        let _ = self.tx_input.unbounded_send(DriverInput::StreamMessage {
            stream_id,
            message: msg,
        });
    }

    pub(crate) fn dispatch_command(&mut self, command_id: CommandId, command: Command) {
        let _ = self.tx_input.unbounded_send(DriverInput::Command {
            command_id,
            command: Box::new(command),
        });
    }

    pub(crate) fn tick(&mut self) {
        let _ = self.tx_input.unbounded_send(DriverInput::Tick);
    }

    pub(crate) fn step(&mut self, now: UnixTimestampMillis) -> EventResults {
        *self.now.borrow_mut() = now;
        self.executor.run_until_stalled();

        let mut event_results = EventResults::default();
        while let Ok(Some(evt)) = self.rx_output.try_next() {
            match evt {
                DriverOutput::CommandCompleted { command_id, result } => {
                    event_results
                        .completed_commands
                        .insert(command_id, Ok(result));
                }
                DriverOutput::Stream { stream_id, event } => {
                    event_results
                        .new_stream_events
                        .entry(stream_id)
                        .or_default()
                        .push(event);
                }
                DriverOutput::Task { task, reply } => {
                    self.io_tasks.insert(task.id(), reply);
                    event_results.new_tasks.push(task);
                }
                DriverOutput::EndpointRequest {
                    endpoint_id,
                    request_id,
                    request,
                } => {
                    event_results
                        .new_requests
                        .entry(endpoint_id)
                        .or_default()
                        .push(NewRequest {
                            id: request_id,
                            request,
                        });
                }
                DriverOutput::DocEvent { doc_id, event } => {
                    event_results
                        .notifications
                        .entry(doc_id)
                        .or_default()
                        .push(event);
                }
                DriverOutput::PeersChanged(new_peers) => {
                    event_results.peer_status_changes.extend(new_peers);
                }
            }
        }

        if self.tx_input.is_closed() {
            event_results.stopped = true;
        }

        event_results
    }
}

pub(crate) struct DriveBeelayArgs<R: rand::Rng + rand::CryptoRng + Clone + 'static> {
    pub(crate) rng: R,
    pub(crate) now: Rc<RefCell<UnixTimestampMillis>>,
    pub(crate) tx_driver_events: mpsc::UnboundedSender<DriverOutput>,
    pub(crate) rx_input: mpsc::UnboundedReceiver<DriverInput>,
    pub(crate) verifying_key: VerifyingKey,
    pub(crate) load_complete: oneshot::Sender<loading::LoadedParts<R>>,
    pub(crate) session_duration: Duration,
}

pub(crate) async fn run<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    args: DriveBeelayArgs<R>,
) {
    // Create a future that we can safely catch panics from
    // let future = std::panic::AssertUnwindSafe(run_inner(
    let future = run_inner(args);
    future.await

    // match future.catch_unwind().await {
    //     Ok(()) => {
    //         tracing::trace!("Beelay event loop completed normally");
    //     }
    //     Err(panic) => {
    //         tracing::error!(?panic, "Beelay event loop panicked");
    //         if let Some(string) = panic.downcast_ref::<String>() {
    //             tracing::error!("Panic message: {}", string);
    //         } else if let Some(str) = panic.downcast_ref::<&str>() {
    //             tracing::error!("Panic message: {}", str);
    //         }
    //     }
    // }
}

async fn run_inner<R: rand::Rng + rand::CryptoRng + Clone + 'static>(
    DriveBeelayArgs {
        now,
        rng,
        mut rx_input,
        tx_driver_events,
        verifying_key,
        load_complete,
        session_duration,
    }: DriveBeelayArgs<R>,
) {
    // The tx end of this is part of `State::streams`. New messages fired by Streams::send_request
    // or during other stream processing are sent to this channel and processed below
    let (tx_outbound_stream_events, mut rx_outbound_stream_events) = mpsc::unbounded();
    // The tx end of this is part of `State::endpoints`. New requests fired by Endpoints::send_request
    // are sent to this channel and processed below
    let (tx_outbound_endpoint_msgs, mut rx_outbound_endpoint_msgs) = mpsc::unbounded();

    let io = IoHandle::new(tx_driver_events.clone());

    // First load the beelay
    let (state, mut keyhive_rx) = {
        let signer = Signer::new(verifying_key, io.clone());

        let load_docs = loading::load_docs(io.clone());
        let load_keyhive = loading::load_keyhive(io.clone(), rng.clone(), signer.clone());
        let (docs, (keyhive, keyhive_rx)) = futures::future::join(load_docs, load_keyhive).await;
        let peer_id = keyhive.active().borrow().verifying_key().into();

        let state = Rc::new(RefCell::new(State::new(
            rng,
            signer,
            keyhive,
            docs,
            session_duration,
            tx_outbound_stream_events,
            tx_outbound_endpoint_msgs,
        )));
        if load_complete
            .send(loading::LoadedParts {
                state: state.clone(),
                peer_id,
            })
            .is_err()
        {
            tracing::warn!("load complete listener went away, stopping driver");
            return;
        }
        (state, keyhive_rx)
    };

    // Now process

    // Tasks storing events emitted by keyhive
    let mut running_keyhive_event_stores = FuturesUnordered::new();
    // Commands which are waiting on IO
    let mut running_commands = FuturesUnordered::new();
    // Requests which were sent over a stream and which are waiting on IO
    let mut inbound_stream_requests = FuturesUnordered::new();
    // Outbound stream messages which are waiting to be signed
    let mut signing_stream_messages = FuturesUnordered::new();
    // Outbound endpoint messages which are waiting to be signed
    let mut signing_endpoint_messages = FuturesUnordered::new();
    let mut run_state = RunState::Running;
    let stopper = crate::stopper::Stopper::new();

    let ctx = TaskContext::new(now.clone(), state.clone(), io, stopper.clone());
    let mut loops = sync_loops::SyncLoops::new();

    let mut known_docs = ctx
        .state()
        .keyhive()
        .try_known_docs()
        .expect("keyhive should be available at this point");

    loop {
        let mut current_archive_keys: Vec<StorageKey> = Vec::new();

        if run_state == RunState::Stopping {
            tracing::trace!(
                num_commands = running_commands.len(),
                keyhive_event_stores_done = running_keyhive_event_stores.is_empty(),
                streams_finished = ctx.state().streams().finished(),
                signing_streams_finished = signing_stream_messages.is_empty(),
                signing_endpoint_finished = signing_endpoint_messages.is_empty(),
                "checking if we can stop"
            );
            if running_commands.is_empty()
                && running_keyhive_event_stores.is_empty()
                && ctx.state().streams().finished()
                && signing_stream_messages.is_empty()
                && signing_endpoint_messages.is_empty()
            {
                stopper.stop();
                break;
            }
        }

        futures::select! {
            input = rx_input.select_next_some() => {
                match input {
                    DriverInput::Command{command_id, command} => {
                        if let commands::Command::Stop = *command {
                            if run_state == RunState::Running {
                                tracing::debug!("starting graceful shutdown");
                                stopper.stop();
                                ctx.state().streams().stop();
                                run_state = RunState::Stopping;
                            }
                        } else {
                            let ctx = ctx.clone();
                            let handler = async move {
                                let result = commands::handle_command(ctx, *command).await;
                                (command_id, result)
                            };
                            running_commands.push(handler);
                        }
                    },
                    DriverInput::StreamMessage { stream_id, message } => {
                        match ctx.state().streams().handle_message(ctx.now(), stream_id, message) {
                            Ok(Some(HandledMessage::NewRequest { from, req, id })) => {
                                let ctx = ctx.clone();
                                let handler = async move {
                                    let result = request_handlers::handle_request(ctx, Some(stream_id), *req, from).await;
                                    (stream_id, id, result)
                                };
                                inbound_stream_requests.push(handler);
                            },
                            Ok(None) => {}
                            Err(e) => {
                                tracing::error!(err=?e, "error handling stream message");
                            }
                        }
                    }
                    DriverInput::Tick => {
                        tracing::trace!(now=?now.borrow().clone(), "tick");
                    }
                }
            }
            outbound_endpoint_msg = rx_outbound_endpoint_msgs.select_next_some() => {
                let (endpoint_id, request_id, msg) = outbound_endpoint_msg;
                let signer = ctx.signer();
                signing_endpoint_messages.push(async move {
                    let signed_msg = auth::Signed::try_sign(signer, msg).await.expect("failed to sign message");
                    (endpoint_id, request_id, signed_msg)
                })
            },
            signing_endpoint_messages = signing_endpoint_messages.select_next_some() => {
                let (endpoint_id, request_id, signed_msg) = signing_endpoint_messages;
                let _ = tx_driver_events.unbounded_send(DriverOutput::EndpointRequest {
                    endpoint_id,
                    request_id,
                    request: EndpointRequest(signed_msg),
                });
            },
            outbound_stream_evt = rx_outbound_stream_events.select_next_some() => {
                let (stream_id, evt) = outbound_stream_evt;
                let signer = ctx.signer();
                signing_stream_messages.push(async move {
                    let signed_evt = match evt {
                        UnsignedStreamEvent::Close => StreamEvent::Close,
                        UnsignedStreamEvent::Send(msg) => {
                            let signed = msg.sign(signer).await;
                            StreamEvent::Send(signed.encode())
                        }
                    };
                    (stream_id, signed_evt)
                })
            },
            inbound_stream_req_complete = inbound_stream_requests.select_next_some() => {
                let (stream_id, conn_id, resp) = inbound_stream_req_complete;
                if let Err(e) = ctx.state().streams().send_response(ctx.now().as_secs(), stream_id, conn_id, resp) {
                    tracing::warn!(err=?e, "error sending response for completed inbound stream request");
                }
            }
            signed = signing_stream_messages.select_next_some() => {
                let (stream_id, event) = signed;
                let _ = tx_driver_events.unbounded_send(DriverOutput::Stream { stream_id, event });
            },
            keyhive_event = keyhive_rx.select_next_some() => {
                // horrible hack because at the moment keyhive events don't include secret keys
                let ctx = ctx.clone();
                let superceded_archives = std::mem::take(&mut current_archive_keys);
                let task = async move {
                    keyhive_storage::store_event(ctx.clone(), keyhive_event).await;
                    let archive = ctx.state().keyhive().archive().await;
                    let archive_path = keyhive_storage::store_archive(ctx.clone(), archive).await;
                    let deletes = superceded_archives.into_iter().map({
                        let ctx = ctx.clone();
                        move |key| {
                            let ctx = ctx.clone();
                            async move {
                                tracing::debug!(%key, "deleting superceded archive key");
                                ctx.clone().storage().delete(key.clone()).await;
                                tracing::debug!(%key, "finished deleting superceded archive key");
                            }
                        }
                    });
                    futures::future::join_all(deletes).await;
                    archive_path
                };
                running_keyhive_event_stores.push(task);
            }
            finished_command = running_commands.select_next_some() => {
                let (command_id, result) = finished_command;
                let _ = tx_driver_events.unbounded_send(DriverOutput::CommandCompleted{ command_id, result });
            }
            stored_archive_path = running_keyhive_event_stores.select_next_some() => {
                if let Some(path) = stored_archive_path {
                    current_archive_keys.push(path);
                }
            }
            _loop_result = loops.process_pending(&ctx).fuse() => {
                tracing::trace!("sync loop completed");
            }
        }

        loops.reconcile(&ctx);
        ctx.state().sessions().expire_sessions(*now.borrow());
        let changed = ctx.state().streams().take_changed();
        if !changed.is_empty() {
            let _ = tx_driver_events.unbounded_send(DriverOutput::PeersChanged(
                changed
                    .into_iter()
                    .map(|info| (info.peer_id, info))
                    .collect(),
            ));
        }
        if let Some(docs_after) = ctx.state().keyhive().try_known_docs() {
            if docs_after != known_docs {
                let new_docs = docs_after.difference(&known_docs);
                for doc in new_docs {
                    ctx.io().new_doc_event(*doc, DocEvent::Discovered);
                }
                known_docs = docs_after;
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RunState {
    Running,
    Stopping,
    #[allow(dead_code)]
    Stopped,
}

impl RunState {
    #[allow(dead_code)]
    fn is_running(&self) -> bool {
        matches!(self, RunState::Running)
    }
}

#[derive(Debug)]
pub(crate) enum DriverOutput {
    CommandCompleted {
        command_id: CommandId,
        result: CommandResult,
    },
    Stream {
        stream_id: streams::StreamId,
        event: streams::StreamEvent,
    },
    Task {
        task: IoTask,
        reply: oneshot::Sender<IoResult>,
    },
    EndpointRequest {
        endpoint_id: EndpointId,
        request_id: OutboundRequestId,
        request: EndpointRequest,
    },
    DocEvent {
        doc_id: DocumentId,
        event: DocEvent,
    },
    PeersChanged(HashMap<PeerId, ConnectionInfo>),
}

pub(crate) enum DriverInput {
    Command {
        command_id: CommandId,
        command: Box<Command>,
    },
    StreamMessage {
        stream_id: streams::StreamId,
        message: Vec<u8>,
    },
    Tick,
}
