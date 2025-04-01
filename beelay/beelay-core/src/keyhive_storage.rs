use keyhive_core::{
    crypto::digest::Digest,
    event::{static_event::StaticEvent, Event},
};

use crate::{
    parse::{self, Parse},
    serialization::{hex, Encode},
    CommitHash, Signer, StorageKey, TaskContext,
};

// Abstract over storage so we can use this when loading as well as when saving
pub(crate) trait Storage {
    async fn load_range(
        &self,
        prefix: StorageKey,
    ) -> std::collections::HashMap<StorageKey, Vec<u8>>;
    async fn load(&self, key: StorageKey) -> Option<Vec<u8>>;
    async fn put(&self, storage_key: StorageKey, value: Vec<u8>);
}

impl crate::keyhive_storage::Storage for crate::io::IoHandle {
    async fn load_range(
        &self,
        prefix: StorageKey,
    ) -> std::collections::HashMap<StorageKey, Vec<u8>> {
        crate::task_context::Storage::new(self)
            .load_range(prefix)
            .await
    }

    async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        crate::task_context::Storage::new(self).load(key).await
    }

    async fn put(&self, storage_key: StorageKey, value: Vec<u8>) {
        crate::task_context::Storage::new(self)
            .put(storage_key, value)
            .await
    }
}

impl<R> Storage for TaskContext<R>
where
    R: rand::Rng + rand::CryptoRng,
{
    async fn load_range(
        &self,
        prefix: StorageKey,
    ) -> std::collections::HashMap<StorageKey, Vec<u8>> {
        self.storage().load_range(prefix).await
    }

    async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        self.storage().load(key).await
    }

    async fn put(&self, storage_key: StorageKey, value: Vec<u8>) {
        self.storage().put(storage_key, value).await;
    }
}

impl<'a> Storage for crate::task_context::Storage<'a> {
    async fn load_range(
        &self,
        prefix: StorageKey,
    ) -> std::collections::HashMap<StorageKey, Vec<u8>> {
        self.load_range(prefix).await
    }

    async fn load(&self, key: StorageKey) -> Option<Vec<u8>> {
        self.load(key).await
    }

    async fn put(&self, storage_key: StorageKey, value: Vec<u8>) {
        self.put(storage_key, value).await;
    }
}

pub(crate) async fn store_event<S: Storage>(
    ctx: S,
    event: Event<Signer, CommitHash, crate::keyhive::Listener>,
) {
    let event = StaticEvent::from(event);
    let digest = Digest::hash(&event).raw;
    let storage_key = StorageKey::auth()
        .push("events")
        .push(hex::encode(digest.as_bytes()));
    ctx.put(storage_key, event.encode()).await;
}

pub(crate) async fn load_events<S: Storage>(ctx: S) -> Vec<StaticEvent<CommitHash>> {
    let storage_key = StorageKey::auth().push("events");
    let raw = ctx.load_range(storage_key).await;
    let mut events = Vec::new();
    for event in raw.into_values() {
        let input = parse::Input::new(&event);
        let Ok((_, event)) = StaticEvent::parse(input).inspect_err(|e| {
            tracing::error!(err=?e, "failed to parse stored keyhive event");
        }) else {
            continue;
        };
        events.push(event);
    }
    events
}

pub(crate) async fn load_archives<S: Storage>(
    ctx: S,
) -> (
    Vec<StorageKey>,
    Vec<keyhive_core::archive::Archive<CommitHash>>,
) {
    let prefix = StorageKey::auth().push("archive");
    let raw_archives = ctx.load_range(prefix).await;
    let mut keys = Vec::new();
    let mut archives = Vec::new();
    tracing::trace!(num_archives = raw_archives.len(), "loading raw archives");
    for (key, v) in raw_archives {
        keys.push(key);
        if let Some(archive) = bincode::deserialize(&v)
            .inspect_err(|e| {
                tracing::error!(err=?e, "failed to decode stored keyhive archive");
            })
            .ok()
        {
            archives.push(archive);
        }
    }
    (keys, archives)
}

pub(crate) async fn store_archive<S: Storage>(
    ctx: S,
    archive: keyhive_core::archive::Archive<CommitHash>,
) -> Option<StorageKey> {
    let Ok(raw) = bincode::serialize(&archive).inspect_err(|e| {
        tracing::error!(err=?e, "failed to encode keyhive archive");
    }) else {
        return None;
    };
    let raw_hash = blake3::hash(&raw);
    let key = StorageKey::auth()
        .push("archive")
        .push(hex::encode(raw_hash.as_bytes()));
    ctx.put(key.clone(), raw).await;
    Some(key)
}
