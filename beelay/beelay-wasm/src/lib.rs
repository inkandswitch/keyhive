use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
};

use beelay_core::{
    conn_info::ConnState,
    doc_status::DocEvent,
    io::IoResult,
    keyhive::{AddMemberToGroup, KeyhiveCommandResult, RemoveMemberFromGroup},
    loading, CommandId, CommandResult, DocumentId, Event, PeerId, StreamEvent,
    StreamId, UnixTimestampMillis,
};
use futures::{channel::oneshot, stream::FuturesUnordered, StreamExt};
use js_sys::{Array, Function, Object, Reflect};
use js_wrappers::{JsAccess, JsBundle, JsBundleSpec, JsCommit, JsCommitOrBundle, KeyhiveEntity};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

mod add_member_args;
mod js_wrappers;
mod membered;
pub(crate) use membered::Membered;
mod remove_member_args;
mod signer;
mod storage;
mod stream;
mod stream_config;
mod utils;

#[wasm_bindgen(typescript_custom_section)]
const TS: &'static str = r#"
export type Config = {
    storage: StorageAdapter
    signer: Signer
}

export type StorageKey  = string[]
export type PeerId = string
export type DocumentId = string

export interface Signer {
    verifyingKey: Uint8Array
    sign(message: Uint8Array): Promise<Uint8Array>
}

export interface StorageAdapter {
  load(key: string[]): Promise<Uint8Array | undefined>
  loadRange(
    prefix: string[],
  ): Promise<Map<StorageKey, Uint8Array>>
  save(key: string[], data: Uint8Array): Promise<void>
  remove(key: string[]): Promise<void>
  listOneLevel(prefix: string[]): Promise<Array<string[]>>
}

export type Audience =
  | { type: "peerId"; peerId: PeerId }
  | { type: "serviceName"; serviceName: string }

export type StreamConfig =
  | { direction: "accepting"; receiveAudience?: string | null }
  | { direction: "connecting"; remoteAudience: Audience }

export interface Stream {
  on(event: "message", f: (msg: Uint8Array) => void): void
  off(event: "message", f: (msg: Uint8Array) => void): void
  on(event: "disconnect", f: () => void): void
  off(event: "disconnect", f: () => void): void
  closed(): Promise<void>
  recv(msg: Uint8Array): Promise<void>
  disconnect(): void
}

export type CommitHash = string

export type Commit = {
    hash: CommitHash,
    parents: CommitHash[],
    contents: Uint8Array,
}

export type Bundle = {
  start: CommitHash
  end: CommitHash
  checkpoints: CommitHash[]
  contents: Uint8Array
}

export type CommitOrBundle =
  | ({ type: "commit" } & Commit)
  | ({ type: "bundle" } & Bundle)

export type BundleSpec = {
    doc: DocumentId,
    start: CommitHash,
    end: CommitHash,
    checkpoints: CommitHash[],
}

export type Access = "pull" | "read" | "write" | "admin"

export type HexContactCard = string
export type Membered =
    | { type: "group", id: PeerId }
    | { type: "document", id: DocumentId }
export type KeyhiveEntity =
    | { type: "individual", contactCard: HexContactCard }
    | { type: "public" }
    | Membered

export type CreateDocArgs = {
    initialCommit: Commit,
    otherParents?: Array<KeyhiveEntity>,
}
export type CreateGroupArgs = {
    otherParents?: Array<KeyhiveEntity>,
}
export type AddMemberArgs =
    | { groupId: PeerId,
        member: KeyhiveEntity,
        access: Access,
    }
    | { docId: DocumentId,
        member: KeyhiveEntity,
        access: Access,
    }
export type RemoveMemberArgs =
    | { groupId: PeerId,
        member: KeyhiveEntity,
    }
    | { docId: DocumentId,
        member: KeyhiveEntity,
    }
export type AddCommitArgs = {
    docId: DocumentId,
    commits: Commit[],
}
export type AddBundleArgs = {
    docId: DocumentId,
    bundle: Bundle,
}

interface BeelayEvents {
    "peer-sync-state": {peerId: PeerId, status: "listening" | "connected"},
    "doc-event": {docId: DocumentId, event: {type: "data", data: CommitOrBundle } | { type: "discovered" }},
}
interface Beelay {
  on<T extends keyof BeelayEvents>(
    eventName: T,
    handler: (args: BeelayEvents[T]) => void,
  ): void;
  off<T extends keyof BeelayEvents>(
    eventName: T,
    handler: (args: BeelayEvents[T]) => void,
  ): void;
  createGroup(args?: CreateGroupArgs): Promise<PeerId>;
}
"#;

#[wasm_bindgen]
extern "C" {
    fn setInterval(closure: &Closure<dyn FnMut()>, time: u32) -> i32;
    fn clearInterval(id: i32);

    #[wasm_bindgen(typescript_type = "Signer")]
    pub type Signer;

    #[wasm_bindgen(typescript_type = "StorageAdapter")]
    pub type StorageAdapter;

    #[wasm_bindgen(typescript_type = "Config")]
    pub type TsConfig;

    #[wasm_bindgen(typescript_type = "Stream")]
    pub type TsStream;
    #[wasm_bindgen(typescript_type = "StreamConfig")]
    pub type TsStreamConfig;

    #[wasm_bindgen(typescript_type = "DocumentId")]
    pub type TsDocumentId;
    #[wasm_bindgen(typescript_type = "CommitHash")]
    pub type TsCommitHash;
    #[wasm_bindgen(typescript_type = "Commit")]
    pub type TsCommit;
}

#[derive(Clone)]
#[wasm_bindgen]
pub struct Beelay {
    inner: Rc<RefCell<Inner>>,
}

#[wasm_bindgen]
impl Beelay {
    #[wasm_bindgen]
    pub async fn load(config: TsConfig) -> Result<Self, JsError> {
        console_error_panic_hook::set_once();
        if !config.obj.is_object() {
            return Err(JsError::new("config must be an object"));
        }
        let js_storage = Reflect::get(&config, &"storage".into())
            .map_err(|_| JsError::new("failed to get config.storage"))?;
        let js_signer = Reflect::get(&config, &"signer".into())
            .map_err(|_| JsError::new("failed to get config.signer"))?;

        let storage = storage::JsStorage::new(js_storage)?;
        let signer = signer::Signer::new(js_signer)?;
        let verifying_key = signer.verifying_key();
        let io = Rc::new(Io { storage, signer });

        let config = beelay_core::Config::new(rand::rngs::OsRng, verifying_key);
        let mut step = beelay_core::Beelay::load(config, now());

        let mut running_tasks = FuturesUnordered::new();

        let mut core = 'outer: loop {
            let loading = match step {
                loading::Step::Loaded(beelay, tasks) => {
                    for task in tasks {
                        running_tasks.push(dispatch_task(io.clone(), task));
                    }
                    break 'outer beelay;
                }
                loading::Step::Loading(loading, tasks) => {
                    for task in tasks {
                        running_tasks.push(dispatch_task(io.clone(), task));
                    }
                    loading
                }
            };
            let next_result = running_tasks.select_next_some().await?;
            step = loading.handle_io_complete(now(), next_result);
        };

        while !running_tasks.is_empty() {
            let next_result = running_tasks.select_next_some().await?;
            let event = beelay_core::Event::io_complete(next_result);
            core.handle_event(now(), event)?;
        }

        let inner = Rc::new(RefCell::new(Inner {
            io,
            core,
            running_commands: HashMap::new(),
            creating_streams: HashMap::new(),
            ready_streams: HashMap::new(),
            cb: None,
            interval_id: None,
            peer_listeners: Vec::new(),
            doc_change_listeners: Vec::new(),
            awaiting_sync: HashMap::new(),
            awaiting_docs: HashMap::new(),
            awaiting_stop: Vec::new(),
            stopped: false,
        }));
        let beelay = Self { inner };

        let cb = Closure::new({
            let beelay = beelay.clone();
            move || {
                beelay.tick();
            }
        });
        let interval_id = setInterval(&cb, 1000);
        beelay.inner.borrow_mut().cb = Some(Rc::new(cb));
        beelay.inner.borrow_mut().interval_id = Some(interval_id);

        Ok(beelay)
    }

    #[wasm_bindgen(getter = "peerId", unchecked_return_type = "PeerId")]
    pub fn peer_id(&self) -> JsValue {
        self.inner.borrow_mut().core.peer_id().to_string().into()
    }

    #[wasm_bindgen(
        js_name = "createContactCard",
        unchecked_return_type = "HexContactCard"
    )]
    pub async fn contact_card(&self) -> Result<JsValue, JsError> {
        let (command_id, event) = Event::create_contact_card();
        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .running_commands
            .insert(command_id, tx);
        self.handle_event(event);
        match rx.await {
            Ok(result) => match result {
                CommandResult::Keyhive(KeyhiveCommandResult::CreateContactCard(card)) => match card
                {
                    Ok(c) => Ok(c.to_hex_string().into()),
                    Err(e) => Err(JsError::new(&format!(
                        "Failed to create contact card: {}",
                        e
                    ))),
                },
                _ => return Err(JsError::new("unexpected command result")),
            },
            Err(err) => Err(JsError::new(&format!(
                "Failed to get contact card: {}",
                err
            ))),
        }
    }

    #[wasm_bindgen(js_name = "createDoc", unchecked_return_type = "DocumentId")]
    pub async fn create_document(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreateDocArgs")] args: &JsValue,
    ) -> Result<JsValue, JsError> {
        if !args.is_object() {
            return Err(JsError::new("args must be an object"));
        }
        let initial_commit = Reflect::get(&args, &"initialCommit".into())
            .map_err(|_| JsError::new("Failed to get initial commit"))?;
        let other_parents = Reflect::get(&args, &"otherParents".into())
            .map_err(|_| JsError::new("Failed to get additional parents"))?;

        let js_commit: js_wrappers::JsCommit = serde_wasm_bindgen::from_value(initial_commit)
            .map_err(|e| JsError::new(&format!("Failed to deserialize initial commit: {}", e)))?;

        let other_parents = if other_parents.is_null() || other_parents.is_undefined() {
            None
        } else {
            let other_parents = other_parents
                .dyn_into::<Array>()
                .map_err(|_| JsError::new("Failed to convert additional parents to array"))?
                .iter()
                .enumerate()
                .map(|(index, parent)| {
                    let parent =
                        serde_wasm_bindgen::from_value::<KeyhiveEntity>(parent).map_err(|e| {
                            JsError::new(&format!("Failed to deserialize parent {}: {}", index, e))
                        })?;
                    Ok::<_, JsError>(parent.into())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some(other_parents)
        };

        let (command_id, event) =
            Event::create_doc(js_commit.into(), other_parents.unwrap_or_default());
        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .running_commands
            .insert(command_id, tx);
        self.handle_event(event);
        match rx.await {
            Ok(result) => match result {
                CommandResult::CreateDoc(doc) => match doc {
                    Ok(doc) => Ok(doc.to_string().into()),
                    Err(err) => Err(JsError::new(&format!("Failed to create document: {}", err))),
                },
                _ => Err(JsError::new("Unexpected command result")),
            },
            Err(_) => Err(JsError::new("beelay has stopped")),
        }
    }

    #[wasm_bindgen(js_name = createGroup, skip_typescript)]
    pub async fn create_group(
        &self,
        #[wasm_bindgen(unchecked_param_type = "CreateGroupArgs?")] args: JsValue,
    ) -> Result<JsValue, JsError> {
        let other_parents = if !(args.is_null() || args.is_undefined()) {
            if !args.is_object() {
                return Err(JsError::new("create group argument was not an object"));
            }
            let other_parents = Reflect::get(&args, &"otherParents".into())
                .map_err(|_| JsError::new("Failed to get additional parents"))?;

            if other_parents.is_null() || other_parents.is_undefined() {
                Vec::new()
            } else {
                let other_parents = other_parents
                    .dyn_into::<Array>()
                    .map_err(|_| JsError::new("Failed to convert additional parents to array"))?
                    .iter()
                    .enumerate()
                    .map(|(index, parent)| {
                        let parent = serde_wasm_bindgen::from_value::<KeyhiveEntity>(parent)
                            .map_err(|e| {
                                JsError::new(&format!(
                                    "Failed to deserialize parent {}: {}",
                                    index, e
                                ))
                            })?;
                        Ok::<_, JsError>(parent.into())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                other_parents
            }
        } else {
            Vec::new()
        };

        let (command_id, event) = Event::create_group(other_parents);
        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .running_commands
            .insert(command_id, tx);
        self.handle_event(event);
        match rx.await {
            Ok(result) => match result {
                CommandResult::Keyhive(KeyhiveCommandResult::CreateGroup(result)) => match result {
                    Ok(group_id) => Ok(group_id.to_string().into()),
                    Err(err) => Err(JsError::new(&format!("Failed to create group: {}", err))),
                },
                _ => Err(JsError::new("Unexpected command result")),
            },
            Err(_) => Err(JsError::new("beelay has stopped")),
        }
    }

    #[wasm_bindgen(js_name = "addMember")]
    pub async fn add_member(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AddMemberArgs")] args: JsValue,
    ) -> Result<(), JsError> {
        if !args.is_object() {
            return Err(JsError::new("argument was not an object"));
        }

        let args: add_member_args::AddMemberArgs = serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsError::new(&format!("invalid arguments: {:?}", e)))?;

        match args.membered {
            Membered::Group(group_id) => {
                let (command_id, event) = Event::add_member_to_group(AddMemberToGroup {
                    access: args.access.into(),
                    group_id,
                    member: args.member.into(),
                });
                let (tx, rx) = oneshot::channel();
                self.inner
                    .borrow_mut()
                    .running_commands
                    .insert(command_id, tx);
                self.handle_event(event);
                match rx.await {
                    Ok(result) => match result {
                        CommandResult::Keyhive(KeyhiveCommandResult::AddMemberToGroup(result)) => {
                            match result {
                                Ok(_) => Ok(()),
                                Err(err) => Err(JsError::new(&format!(
                                    "Failed to add member to group: {}",
                                    err
                                ))),
                            }
                        }
                        _ => Err(JsError::new("Unexpected command result")),
                    },
                    Err(_) => Err(JsError::new("beelay has stopped")),
                }
            }
            Membered::Document(doc_id) => {
                let (command_id, event) =
                    Event::add_member_to_doc(doc_id, args.member.into(), args.access.into());
                let (tx, rx) = oneshot::channel();
                self.inner
                    .borrow_mut()
                    .running_commands
                    .insert(command_id, tx);
                self.handle_event(event);
                match rx.await {
                    Ok(result) => match result {
                        CommandResult::Keyhive(KeyhiveCommandResult::AddMemberToDoc) => Ok(()),
                        _ => Err(JsError::new("Unexpected command result")),
                    },
                    Err(_) => Err(JsError::new("beelay has stopped")),
                }
            }
        }
    }

    #[wasm_bindgen(js_name = "removeMember")]
    pub async fn remove_member(
        &self,
        #[wasm_bindgen(unchecked_param_type = "RemoveMemberArgs")] args: JsValue,
    ) -> Result<(), JsError> {
        if !args.is_object() {
            return Err(JsError::new("argument was not an object"));
        }

        let args: remove_member_args::RemoveMemberArgs = serde_wasm_bindgen::from_value(args)
            .map_err(|e| JsError::new(&format!("invalid arguments: {:?}", e)))?;

        match args.membered {
            Membered::Group(group_id) => {
                let (command_id, event) = Event::remove_member_from_group(RemoveMemberFromGroup {
                    group_id,
                    member: args.member.into(),
                });
                let (tx, rx) = oneshot::channel();
                self.inner
                    .borrow_mut()
                    .running_commands
                    .insert(command_id, tx);
                self.handle_event(event);
                match rx.await {
                    Ok(result) => match result {
                        CommandResult::Keyhive(KeyhiveCommandResult::RemoveMemberFromGroup(
                            result,
                        )) => match result {
                            Ok(_) => Ok(()),
                            Err(err) => Err(JsError::new(&format!(
                                "Failed to remove member from group: {}",
                                err
                            ))),
                        },
                        _ => Err(JsError::new("Unexpected command result")),
                    },
                    Err(_) => Err(JsError::new("beelay has stopped")),
                }
            }
            Membered::Document(doc_id) => {
                let (command_id, event) = Event::remove_member_from_doc(doc_id, args.member.into());
                let (tx, rx) = oneshot::channel();
                self.inner
                    .borrow_mut()
                    .running_commands
                    .insert(command_id, tx);
                self.handle_event(event);
                match rx.await {
                    Ok(result) => match result {
                        CommandResult::Keyhive(KeyhiveCommandResult::RemoveMemberFromDoc(
                            result,
                        )) => match result {
                            Ok(_) => Ok(()),
                            Err(err) => Err(JsError::new(&format!(
                                "Failed to remove member from document: {}",
                                err
                            ))),
                        },
                        _ => Err(JsError::new("Unexpected command result")),
                    },
                    Err(_) => Err(JsError::new("beelay has stopped")),
                }
            }
        }
    }

    #[wasm_bindgen(js_name = "addCommits", unchecked_return_type = "BundleSpec[]")]
    pub async fn add_commits(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AddCommitArgs")] args: JsValue,
    ) -> Result<JsValue, JsError> {
        let opts = args
            .dyn_into::<Object>()
            .map_err(|_| JsError::new("add commits argument was not an object"))?;

        let doc_id = Reflect::get(&opts, &"docId".into())
            .map_err(|_| JsError::new("unable to get args.docId"))?
            .as_string()
            .ok_or_else(|| JsError::new("document ID was not a string"))?
            .parse::<DocumentId>()
            .map_err(|e| JsError::new(&format!("invalid document Id: {:?}", e)))?;

        let commits = Reflect::get(&opts, &"commits".into())
            .map_err(|_| JsError::new("unable to get args.commits"))?
            .dyn_into::<Array>()
            .map_err(|_| JsError::new("commits was not an array"))?
            .iter()
            .enumerate()
            .map(|(i, commit)| {
                let js_commit =
                    serde_wasm_bindgen::from_value::<JsCommit>(commit).map_err(|e| {
                        JsError::new(&format!("invalid commit at index {}: {:?}", i, e))
                    })?;
                Ok(js_commit.into())
            })
            .collect::<Result<Vec<beelay_core::Commit>, JsError>>()?;

        let (command_id, command) = Event::add_commits(doc_id, commits);
        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .running_commands
            .insert(command_id, tx);
        self.handle_event(command);
        match rx.await {
            Ok(result) => match result {
                CommandResult::AddCommits(bundle_specs) => match bundle_specs {
                    Ok(bundle_specs) => {
                        let result = Array::new();
                        for bundle_spec in bundle_specs {
                            let bundle =
                                serde_wasm_bindgen::to_value(&JsBundleSpec::from(bundle_spec))
                                    .unwrap();
                            result.push(&bundle);
                        }
                        Ok(result.into())
                    }
                    Err(err) => Err(JsError::new(&format!("Failed to add commits: {}", err))),
                },
                _ => Err(JsError::new("Unexpected command result")),
            },
            Err(_) => Err(JsError::new("beelay has stopped")),
        }
    }

    #[wasm_bindgen(js_name = "addBundle")]
    pub async fn add_bundle(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AddBundleArgs")] args: JsValue,
    ) -> Result<(), JsError> {
        let opts = args
            .dyn_into::<Object>()
            .map_err(|_| JsError::new("add commits argument was not an object"))?;

        let doc_id = Reflect::get(&opts, &"docId".into())
            .map_err(|_| JsError::new("unable to get args.docId"))?
            .as_string()
            .ok_or_else(|| JsError::new("document ID was not a string"))?
            .parse::<DocumentId>()
            .map_err(|e| JsError::new(&format!("invalid document Id: {:?}", e)))?;

        let bundle = Reflect::get(&opts, &"bundle".into())
            .map_err(|_| JsError::new("unable to get args.commits"))
            .and_then(|val| {
                serde_wasm_bindgen::from_value::<JsBundle>(val)
                    .map_err(|e| JsError::new(&format!("invalid bundle: {:?}", e)))
            })?;

        let (command_id, command) = Event::add_bundle(doc_id, bundle.into());
        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .running_commands
            .insert(command_id, tx);
        self.handle_event(command);
        match rx.await {
            Ok(result) => match result {
                CommandResult::AddBundle(result) => match result {
                    Ok(()) => Ok(()),
                    Err(err) => Err(JsError::new(&format!("Failed to add bundle: {}", err))),
                },
                _ => Err(JsError::new("Unexpected command result")),
            },
            Err(_) => Err(JsError::new("beelay has stopped")),
        }
    }

    #[wasm_bindgen(
        js_name = "loadDocument",
        unchecked_return_type = "Array<CommitOrBundle> | null"
    )]
    pub async fn load_document(&self, doc_id: JsValue) -> Result<JsValue, JsError> {
        let doc_id = doc_id
            .as_string()
            .ok_or_else(|| JsError::new("document ID was not a string"))?
            .parse::<DocumentId>()
            .map_err(|e| JsError::new(&format!("invalid document Id: {:?}", e)))?;

        let result = self.load_document_impl(doc_id).await?;
        Ok(result.unwrap_or_else(|| JsValue::null()))
    }

    #[wasm_bindgen(
        js_name = "waitForDocument",
        unchecked_return_type = "Array<CommitOrBundle>"
    )]
    pub async fn wait_for_document(&self, doc_id: JsValue) -> Result<JsValue, JsError> {
        let doc_id = doc_id
            .as_string()
            .ok_or_else(|| JsError::new("document ID was not a string"))?
            .parse::<DocumentId>()
            .map_err(|e| JsError::new(&format!("invalid document Id: {:?}", e)))?;

        let doc = self.load_document_impl(doc_id).await?;
        if let Some(doc) = doc {
            return Ok(doc);
        }

        let (tx, rx) = oneshot::channel();
        self.inner
            .borrow_mut()
            .awaiting_docs
            .entry(doc_id)
            .or_default()
            .push(tx);
        rx.await.map_err(|_| JsError::new("channel closed"))?;

        let doc = self.load_document_impl(doc_id).await?;
        Ok(doc.expect("doc should be loaded if we received a discover event"))
    }

    async fn load_document_impl(&self, doc_id: DocumentId) -> Result<Option<JsValue>, JsError> {
        let (command_id, command) = Event::load_doc(doc_id);
        let (tx, rx) = oneshot::channel();
        {
            self.inner
                .borrow_mut()
                .running_commands
                .insert(command_id, tx);
        }
        self.handle_event(command);
        match rx.await.map_err(|_| JsError::new("channel closed"))? {
            CommandResult::LoadDoc(result) => {
                if let Some(result) = result {
                    let arr = js_sys::Array::new();
                    for item in result {
                        let item =
                            serde_wasm_bindgen::to_value(&JsCommitOrBundle::from(item)).unwrap();
                        arr.push(&item);
                    }
                    return Ok(Some(arr.into()));
                } else {
                    return Ok(None);
                }
            }
            _ => Err(JsError::new("Unexpected command result")),
        }
    }

    #[wasm_bindgen(js_name = "createStream", unchecked_return_type = "Stream")]
    pub fn create_stream(&self, config: TsStreamConfig) -> Result<JsValue, JsError> {
        let config: stream_config::StreamConfig = serde_wasm_bindgen::from_value(config.obj)?;
        let (command_id, event) = Event::create_stream(config.into());
        let stream = Rc::new(RefCell::new(stream::Stream::new()));
        self.inner
            .borrow_mut()
            .creating_streams
            .insert(command_id, stream.clone());
        self.handle_event(event);
        let stream_handle = stream::StreamHandle::new(self.clone(), stream);
        Ok(JsValue::from(stream_handle))
    }

    pub async fn stop(&self) {
        if self.inner.borrow().stopped {
            return;
        }
        if let Some(interval_id) = self.inner.borrow().interval_id {
            clearInterval(interval_id);
        }
        let (tx, rx) = oneshot::channel();
        self.inner.borrow_mut().awaiting_stop.push(tx);
        let event = Event::stop();
        self.handle_event(event);
        rx.await.ok();
    }

    // skip typescript because we define the type in the TS string at the start of this file
    #[wasm_bindgen(skip_typescript)]
    pub fn on(&self, event_type: &JsValue, callback: JsValue) -> Result<(), JsError> {
        let event_type = event_type
            .as_string()
            .ok_or_else(|| JsError::new(&"event type must be a string"))?;
        let callback = callback
            .dyn_into::<Function>()
            .map_err(|_| JsError::new(&"peer callback must be a function"))?;
        let mut inner = self.inner.borrow_mut();
        match event_type.as_str() {
            "peer-sync-state" => inner.peer_listeners.push(callback),
            "doc-event" => inner.doc_change_listeners.push(callback),
            other => return Err(JsError::new(&format!("unknown event type: {}", other))),
        }
        Ok(())
    }

    #[wasm_bindgen(skip_typescript)]
    pub fn off(&self, event_type: &JsValue, callback: JsValue) -> Result<(), JsError> {
        let event_type = event_type
            .as_string()
            .ok_or_else(|| JsError::new(&"event type must be a string"))?;
        let callback = callback
            .dyn_into::<Function>()
            .map_err(|_| JsError::new(&"peer callback must be a function"))?;
        let mut inner = self.inner.borrow_mut();
        match event_type.as_str() {
            "peer-sync-state" => inner.peer_listeners.retain(|c| c != &callback),
            "doc-event" => inner.doc_change_listeners.retain(|c| c != &callback),
            other => return Err(JsError::new(&format!("unknown event type: {}", other))),
        }
        Ok(())
    }

    pub fn version(&self) -> String {
        "0.1.0".to_string()
    }

    fn tick(&self) {
        self.handle_event(Event::tick());
    }

    #[wasm_bindgen(js_name = waitUntilSynced)]
    pub async fn wait_until_synced(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PeerId")] peer_id: &JsValue,
    ) -> Result<(), JsError> {
        let peer_id = peer_id
            .as_string()
            .ok_or_else(|| JsError::new(&"peerId must be a string"))?
            .parse()
            .map_err(|e| JsError::new(&format!("invalid peerId: {}", e)))?;
        let rx = {
            let mut inner = self.inner.borrow_mut();
            for (_, info) in inner.core.connection_info() {
                if info.peer_id == peer_id
                    && matches!(
                        info.state,
                        ConnState::Listening {
                            last_synced_at: Some(_)
                        }
                    )
                {
                    return Ok(());
                }
            }
            let (tx, rx) = oneshot::channel();
            inner.awaiting_sync.entry(peer_id).or_default().push(tx);
            rx
        };
        let _ = rx.await;
        Ok(())
    }

    fn handle_event(&self, event: Event) {
        let was_stopped = self.is_stopped();
        let mut to_handle = VecDeque::new();
        to_handle.push_back(event);
        while let Some(event) = to_handle.pop_front() {
            let Ok(results) = self.inner.borrow_mut().core.handle_event(now(), event) else {
                self.inner.borrow_mut().stopped = true;
                return;
            };
            if results.stopped {
                if !was_stopped {
                    let awaiting_docs = std::mem::take(&mut self.inner.borrow_mut().awaiting_docs);
                    for sender in awaiting_docs.into_values().flatten() {
                        let _ = sender.send(());
                    }
                    let awaiting_sync = std::mem::take(&mut self.inner.borrow_mut().awaiting_sync);
                    for sender in awaiting_sync.into_values().flatten() {
                        let _ = sender.send(());
                    }
                    let awaiting_stop = std::mem::take(&mut self.inner.borrow_mut().awaiting_stop);
                    for sender in awaiting_stop {
                        let _ = sender.send(());
                    }
                }
                self.inner.borrow_mut().stopped = true;
            }
            for (command_id, command_result) in results.completed_commands {
                let Ok(command_result) = command_result else {
                    continue;
                };
                if let CommandResult::CreateStream(stream_id) = command_result {
                    let Some(stream) = self.inner.borrow_mut().creating_streams.remove(&command_id)
                    else {
                        continue;
                    };
                    let stream::StreamReady {
                        pending_messages,
                        disconnected,
                    } = stream.borrow_mut().set_stream_id(stream_id);
                    self.inner
                        .borrow_mut()
                        .ready_streams
                        .insert(stream_id, stream);
                    if disconnected {
                        let (_, event) = Event::disconnect_stream(stream_id);
                        to_handle.push_back(event);
                    } else {
                        for msg in pending_messages {
                            let (_, event) = Event::handle_message(stream_id, msg);
                            to_handle.push_back(event);
                        }
                    }
                }
                let maybe_tx = self.inner.borrow_mut().running_commands.remove(&command_id);
                if let Some(tx) = maybe_tx {
                    let _ = tx.send(command_result);
                }
            }
            for (stream_id, stream_events) in results.new_stream_events {
                for evt in stream_events {
                    match evt {
                        StreamEvent::Send(msg) => {
                            let stream = {
                                let inner = self.inner.borrow_mut();
                                let Some(stream) = inner.ready_streams.get(&stream_id) else {
                                    continue;
                                };
                                stream.clone()
                            };
                            stream.borrow_mut().emit_send(msg);
                        }
                        StreamEvent::Close => {
                            let disconnect_listeners = {
                                let mut inner = self.inner.borrow_mut();
                                let Some(stream) = inner.ready_streams.remove(&stream_id) else {
                                    continue;
                                };
                                let mut stream = stream.borrow_mut();
                                stream.take_disconnect_listeners()
                            };
                            for listener in disconnect_listeners {
                                let _ = listener.call0(&JsValue::null());
                            }
                        }
                    }
                }
            }
            for task in results.new_tasks {
                let this = self.clone();
                let fut = dispatch_task(this.inner.borrow().io.clone(), task);
                spawn_local(async move {
                    match fut.await {
                        Ok(result) => {
                            let event = Event::io_complete(result);
                            this.handle_event(event);
                        }
                        Err(err) => {
                            web_sys::console::error_1(&format!("task failed: {:?}", err).into());
                        }
                    }
                })
            }
            let mut discovered_docs = HashSet::new();
            if !results.notifications.is_empty() {
                let listeners = self.inner.borrow().doc_change_listeners.clone();
                for (doc_id, changes) in results.notifications {
                    for change in changes {
                        let js_arg = Object::new();
                        let _ = Reflect::set(&js_arg, &"docId".into(), &doc_id.to_string().into());
                        match change {
                            DocEvent::Data { data } => {
                                let js_event = Object::new();
                                let _ = Reflect::set(&js_event, &"type".into(), &"data".into());
                                let js_data =
                                    serde_wasm_bindgen::to_value(&JsCommitOrBundle::from(data))
                                        .unwrap();
                                let _ = Reflect::set(&js_event, &"data".into(), &js_data);
                                let _ = Reflect::set(&js_arg, &"event".into(), &js_event);
                            }
                            DocEvent::Discovered => {
                                discovered_docs.insert(doc_id);
                                let js_event = Object::new();
                                let _ =
                                    Reflect::set(&js_event, &"type".into(), &"discovered".into());
                                let _ = Reflect::set(&js_arg, &"event".into(), &js_event);
                            }
                            DocEvent::AccessChanged { .. } => {
                                continue;
                            }
                        }
                        for listener in &listeners {
                            let _ = listener.call1(&JsValue::null(), &js_arg);
                        }
                    }
                }
            }
            if !results.peer_status_changes.is_empty() {
                let listeners = self.inner.borrow().peer_listeners.clone();
                for (peer, status) in results.peer_status_changes {
                    if matches!(
                        status.state,
                        ConnState::Listening {
                            last_synced_at: Some(_)
                        }
                    ) {
                        if let Some(waiters) = self.inner.borrow_mut().awaiting_sync.remove(&peer) {
                            for waiter in waiters {
                                let _ = waiter.send(());
                            }
                        }
                    }
                    let status = match status.state {
                        ConnState::Syncing { .. } => JsValue::from("syncing"),
                        ConnState::Listening { .. } => JsValue::from("listening"),
                    };
                    let peer_id = peer.to_string();
                    let val = Object::new();
                    Reflect::set(&val, &"status".into(), &status).unwrap();
                    Reflect::set(&val, &"peerId".into(), &peer_id.into()).unwrap();
                    for listener in &listeners {
                        let _ = listener.call1(&JsValue::null(), &val);
                    }
                }
            }

            if !discovered_docs.is_empty() {
                let listeners = discovered_docs
                    .into_iter()
                    .filter_map(|doc_id| {
                        let listeners = self.inner.borrow_mut().awaiting_docs.remove(&doc_id);
                        listeners
                    })
                    .flatten()
                    .collect::<Vec<_>>();
                for listener in listeners {
                    let _ = listener.send(());
                }
            }
        }
    }

    #[wasm_bindgen(js_name=isStopped)]
    pub fn is_stopped(&self) -> bool {
        self.inner.borrow_mut().stopped.into()
    }
}

#[wasm_bindgen(js_name=parseBeelayDocId, unchecked_return_type="DocumentId")]
pub fn parse_beelay_doc_id(
    #[wasm_bindgen(unchecked_param_type = "string")] val: &JsValue,
) -> Result<JsValue, JsError> {
    if let Some(doc_id) = val
        .as_string()
        .ok_or(JsError::new("document id was not a string"))?
        .parse::<DocumentId>()
        .ok()
    {
        Ok(JsValue::from(doc_id.to_string()))
    } else {
        Ok(JsValue::null())
    }
}

struct Io {
    storage: storage::JsStorage,
    signer: signer::Signer,
}

struct Inner {
    io: Rc<Io>,
    running_commands: HashMap<CommandId, oneshot::Sender<CommandResult>>,
    creating_streams: HashMap<CommandId, Rc<RefCell<stream::Stream>>>,
    ready_streams: HashMap<StreamId, Rc<RefCell<stream::Stream>>>,
    core: beelay_core::Beelay<rand::rngs::OsRng>,
    cb: Option<Rc<Closure<dyn FnMut()>>>,
    interval_id: Option<i32>,
    peer_listeners: Vec<Function>,
    doc_change_listeners: Vec<Function>,
    awaiting_sync: HashMap<PeerId, Vec<oneshot::Sender<()>>>,
    awaiting_docs: HashMap<DocumentId, Vec<oneshot::Sender<()>>>,
    awaiting_stop: Vec<oneshot::Sender<()>>,
    stopped: bool,
}

async fn dispatch_task(io: Rc<Io>, task: beelay_core::io::IoTask) -> Result<IoResult, JsError> {
    use beelay_core::io::IoAction;

    let task_id = task.id();
    match task.take_action() {
        IoAction::Load { key } => {
            let result = io.storage.load(key).await?;
            Ok(IoResult::load(task_id, result))
        }
        IoAction::LoadRange { prefix } => {
            let result = io.storage.load_range(prefix).await?;
            Ok(IoResult::load_range(task_id, result))
        }
        IoAction::ListOneLevel { prefix } => {
            let result = io.storage.list_one_level(prefix).await?;
            Ok(IoResult::list_one_level(task_id, result))
        }
        IoAction::Put { key, data } => {
            io.storage.put(key, data).await?;
            Ok(IoResult::put(task_id))
        }
        IoAction::Delete { key } => {
            io.storage.remove(key).await?;
            Ok(IoResult::delete(task_id))
        }
        IoAction::Sign { payload } => {
            let signature = io.signer.sign(&payload).await?;
            Ok(IoResult::sign(task_id, signature))
        }
    }
}

fn now() -> UnixTimestampMillis {
    let now = js_sys::Date::new_0().get_time();
    let now_u128 = now.floor() as u128;
    UnixTimestampMillis::new(now_u128)
}
