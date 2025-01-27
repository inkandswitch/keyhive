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
    tracing::trace!(?event, "storing keyhive event");
    let event = StaticEvent::from(event);
    let digest = Digest::hash(&event).raw;
    let storage_key = StorageKey::auth()
        .push("events")
        .push(hex::encode(digest.as_bytes()));
    ctx.put(storage_key, event.encode()).await;
    tracing::trace!("done storing keyhive event");
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

pub(crate) async fn load_archive<S: Storage>(
    ctx: S,
) -> Option<keyhive_core::archive::Archive<CommitHash>> {
    let key = StorageKey::auth().push("archive");
    let Some(raw) = ctx.load(key).await else {
        return None;
    };
    bincode::deserialize(&raw)
        .inspect_err(|e| {
            tracing::error!(err=?e, "failed to decode stored keyhive archive");
        })
        .ok()
}

pub(crate) async fn save_archive<S: Storage>(
    ctx: S,
    archive: keyhive_core::archive::Archive<CommitHash>,
) {
    let key = StorageKey::auth().push("archive");
    let Ok(raw) = bincode::serialize(&archive).inspect_err(|e| {
        tracing::error!(err=?e, "failed to encode keyhive archive");
    }) else {
        return;
    };
    ctx.put(key, raw).await;
}
