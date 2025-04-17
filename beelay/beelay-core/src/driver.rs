use std::{cell::RefCell, collections::HashMap, future::Future, rc::Rc, time::Duration};

use ed25519_dalek::VerifyingKey;
use futures::{
    channel::{mpsc, oneshot},
    pin_mut,
    stream::FuturesUnordered,
    FutureExt, StreamExt,
};
use keyhive_core::crypto::verifiable::Verifiable;

mod executor;

use crate::{
    commands,
    conn_info::ConnectionInfo,
    doc_status::DocEvent,
    io::{IoHandle, IoResult, IoTask},
    keyhive_storage, loading,
    network::{self, InnerRpcResponse},
    state::State,
    streams::{self, IncomingStreamEvent},
    sync_loops, Command, CommandId, CommandResult, DocumentId, EndpointId, EventResults, IoTaskId,
    NewRequest, OutboundRequestId, PeerId, Signer, StorageKey, TaskContext, UnixTimestampMillis,
};

pub struct SpawnArgs<R> {
    pub(crate) now: Rc<RefCell<UnixTimestampMillis>>,
    pub(crate) rng: R,
    pub(crate) rx_commands: mpsc::UnboundedReceiver<(CommandId, Command)>,
    pub(crate) rx_tick: mpsc::Receiver<()>,
    pub(crate) tx_driver_events: mpsc::UnboundedSender<DriverEvent>,
}

pub(crate) struct Driver {
    now: Rc<RefCell<UnixTimestampMillis>>,
    io_tasks: HashMap<IoTaskId, oneshot::Sender<IoResult>>,
    endpoint_requests: HashMap<OutboundRequestId, oneshot::Sender<network::InnerRpcResponse>>,
    rx_driver_events: mpsc::UnboundedReceiver<DriverEvent>,
    tx_commands: mpsc::UnboundedSender<(CommandId, Command)>,
    tx_tick: mpsc::Sender<()>,
    executor: executor::LocalExecutor,
}

impl Driver {
    pub(crate) fn start<R, F, Fut>(rng: R, now: UnixTimestampMillis, f: F) -> Self
    where
        F: FnOnce(SpawnArgs<R>) -> Fut,
        Fut: Future<Output = ()> + 'static,
    {
        let (tx_driver_events, rx_driver_events) = mpsc::unbounded();
        let (tx_commands, rx_commands) = mpsc::unbounded();
        let (tx_tick, rx_tick) = mpsc::channel(1);
        let now = Rc::new(RefCell::new(now));

        let spawn_args = SpawnArgs {
            now: now.clone(),
            rng,
            rx_commands,
            tx_driver_events,
            rx_tick,
        };
        let fut = f(spawn_args);
        let executor = executor::LocalExecutor::spawn(fut);

        Self {
            now,
            io_tasks: HashMap::new(),
            endpoint_requests: HashMap::new(),
            rx_driver_events,
            tx_tick,
            tx_commands,
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

    pub(crate) fn handle_response(
        &mut self,
        req_id: OutboundRequestId,
        response: InnerRpcResponse,
    ) {
        let Some(reply) = self.endpoint_requests.remove(&req_id) else {
            tracing::warn!("received response for unknown request");
            return;
        };
        let _ = reply.send(response);
    }

    pub(crate) fn dispatch_command(&mut self, command_id: CommandId, command: Command) {
        let _ = self.tx_commands.unbounded_send((command_id, command));
    }

    pub(crate) fn tick(&mut self) {
        let _ = self.tx_tick.try_send(());
    }

    pub(crate) fn step(&mut self, now: UnixTimestampMillis) -> EventResults {
        if self.tx_commands.is_closed() {
            let result = EventResults {
                stopped: true,
                ..Default::default()
            };
            return result;
        }
        *self.now.borrow_mut() = now;
        self.executor.run_until_stalled();

        let mut event_results = EventResults::default();
        while let Ok(Some(evt)) = self.rx_driver_events.try_next() {
            match evt {
                DriverEvent::CommandCompleted { command_id, result } => {
                    event_results
                        .completed_commands
                        .insert(command_id, Ok(result));
                }
                DriverEvent::Stream { stream_id, event } => {
                    event_results
                        .new_stream_events
                        .entry(stream_id)
                        .or_default()
                        .push(event);
                }
                DriverEvent::Task { task, reply } => {
                    self.io_tasks.insert(task.id(), reply);
                    event_results.new_tasks.push(task);
                }
                DriverEvent::EndpointRequest {
                    endpoint_id,
                    request,
                    reply,
                } => {
                    self.endpoint_requests.insert(request.id, reply);
                    event_results
                        .new_requests
                        .entry(endpoint_id)
                        .or_default()
                        .push(request);
                }
                DriverEvent::DocEvent { doc_id, event } => {
                    event_results
                        .notifications
                        .entry(doc_id)
                        .or_default()
                        .push(event);
                }
                DriverEvent::PeersChanged(new_peers) => {
                    event_results.peer_status_changes.extend(new_peers);
                }
            }
        }

        if self.tx_commands.is_closed() {
            event_results.stopped = true;
        }

        event_results
    }
}

pub(crate) struct DriveBeelayArgs<R: rand::Rng + rand::CryptoRng + Clone + 'static> {
    pub(crate) rng: R,
    pub(crate) now: Rc<RefCell<UnixTimestampMillis>>,
    pub(crate) rx_commands: mpsc::UnboundedReceiver<(CommandId, Command)>,
    pub(crate) tx_driver_events: mpsc::UnboundedSender<DriverEvent>,
    pub(crate) rx_tick: mpsc::Receiver<()>,
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
        // state,
        now,
        rng,
        mut rx_commands,
        mut rx_tick,
        tx_driver_events,
        verifying_key,
        load_complete,
        session_duration,
        // rx_keyhive_events: mut keyhive_events,
    }: DriveBeelayArgs<R>,
) {
    // First load the beelay
    let (state, mut keyhive_rx) = {
        let io = IoHandle::new_loading(tx_driver_events.clone());
        let signer = Signer::new(verifying_key, io.clone());

        let load_docs = loading::load_docs(io.clone());
        let load_keyhive = loading::load_keyhive(io, rng.clone(), signer.clone());
        let (docs, (keyhive, keyhive_rx)) = futures::future::join(load_docs, load_keyhive).await;
        let peer_id = keyhive.active().borrow().verifying_key().into();

        let state = Rc::new(RefCell::new(State::new(
            rng,
            signer,
            keyhive,
            docs,
            session_duration,
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
    let mut running_keyhive_event_stores = FuturesUnordered::new();
    let mut running_commands = FuturesUnordered::new();
    let mut run_state = RunState::Running;

    let (tx_inbound_stream_events, rx_inbound_stream_events) = mpsc::unbounded();
    let io_handle = IoHandle::new_driver(TinCans {
        tx_event: tx_driver_events.clone(),
        tx_inbound_stream_events,
    });
    let stopper = crate::stopper::Stopper::new();

    let ctx = TaskContext::new(now.clone(), state.clone(), io_handle, stopper.clone());
    let running_streams = streams::run_streams(ctx.clone(), rx_inbound_stream_events).fuse();
    let mut loops = sync_loops::SyncLoops::new();
    pin_mut!(running_streams);

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
                streams_done = running_streams.is_done(),
                keyhive_event_stores_done = running_keyhive_event_stores.is_empty(),
                "checking if we can stop"
            );
            if running_commands.is_empty()
                && running_streams.is_done()
                && running_keyhive_event_stores.is_empty()
            {
                stopper.stop();
                break;
            }
        }
        futures::select! {
            command = rx_commands.select_next_some() => {
                let (command_id, command) = command;
                if let commands::Command::Stop = command {
                    if run_state == RunState::Running {
                        tracing::debug!("starting graceful shutdown");
                        stopper.stop();
                        run_state = RunState::Stopping;
                    }
                } else {
                    let ctx = ctx.clone();
                    let handler = async move {
                        let result = commands::handle_command(ctx, command).await;
                        (command_id, result)
                    };
                    running_commands.push(handler);
                }
            }
            _ = rx_tick.next() => {
                tracing::trace!(now=?now.borrow().clone(), "tick");
            }
            next_stream_event = running_streams.next() => {
                let Some((stream_id, event)) = next_stream_event else {
                    tracing::trace!("running streams completed");
                    continue;
                };
                let _ = tx_driver_events.unbounded_send(DriverEvent::Stream{ stream_id, event });
            }
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
                let _ = tx_driver_events.unbounded_send(DriverEvent::CommandCompleted{ command_id, result });
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
            let _ = tx_driver_events.unbounded_send(DriverEvent::PeersChanged(
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
pub(crate) enum DriverEvent {
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
        request: NewRequest,
        reply: oneshot::Sender<network::InnerRpcResponse>,
    },
    DocEvent {
        doc_id: DocumentId,
        event: DocEvent,
    },
    PeersChanged(HashMap<PeerId, ConnectionInfo>),
}

/// A handle used to send messages to the environment driving the event loop
#[derive(Clone)]
pub(crate) struct TinCans {
    tx_event: mpsc::UnboundedSender<DriverEvent>,
    tx_inbound_stream_events: mpsc::UnboundedSender<IncomingStreamEvent>,
}

impl TinCans {
    /// Request a new IoTask be performed, the result to be sent to `reply`
    pub(crate) fn new_task(&self, task: IoTask, reply: oneshot::Sender<IoResult>) {
        let _ = self
            .tx_event
            .unbounded_send(DriverEvent::Task { task, reply });
    }

    /// Request a new request be made to `endpoint_id`, the result to be sent to `reply`
    pub(crate) fn new_endpoint_request(
        &self,
        endpoint_id: EndpointId,
        request: NewRequest,
        reply: oneshot::Sender<network::InnerRpcResponse>,
    ) {
        let _ = self.tx_event.unbounded_send(DriverEvent::EndpointRequest {
            endpoint_id,
            request,
            reply,
        });
    }

    /// Emit a new document event
    pub(crate) fn new_doc_event(&self, doc_id: DocumentId, event: DocEvent) {
        let _ = self
            .tx_event
            .unbounded_send(DriverEvent::DocEvent { doc_id, event });
    }

    /// Send a new event to be handled by the stream processing subsystem (streams::run_streams)
    pub(crate) fn new_inbound_stream_event(&self, event: IncomingStreamEvent) {
        let _ = self.tx_inbound_stream_events.unbounded_send(event);
    }
}
