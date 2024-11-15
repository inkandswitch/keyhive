use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use futures::{Future, FutureExt, TryFutureExt};

use crate::{Storage, StorageKey};

pub use error::Error;

/// A wrapper around [`crate::fs_store::FsStore`] that implements [`crate::Storage`]
#[derive(Clone, Debug)]
pub struct FsStorage {
    inner: Arc<Mutex<crate::fs_store::FsStore>>,
    handle: tokio::runtime::Handle,
}

impl FsStorage {
    /// Creates a new [`FsStorage`] from a [`Path`].
    ///
    /// # Errors
    ///
    /// This will attempt to create the root directory and throw an error if
    /// it does not exist.
    ///
    /// # Panics
    ///
    /// If there is not a tokio runtime available
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, std::io::Error> {
        let handle = tokio::runtime::Handle::current();
        let inner = Arc::new(Mutex::new(crate::fs_store::FsStore::open(root)?));
        Ok(Self { inner, handle })
    }

    /// Overrides the tmpdir directory used for temporary files.
    ///
    /// The default is to use the root directory passed to [`FsStorage::open`].
    ///
    /// The tmpdir used must be on the same mount point as the root directory,
    /// otherwise the storage will throw an error on writing data.
    ///
    /// # Errors
    ///
    /// This will attempt to create the tmpdir directory and throw an error if
    /// it does not exist.
    pub fn with_tmpdir<P: AsRef<Path>>(self, tmpdir: P) -> Option<Result<Self, std::io::Error>> {
        let Self { inner, handle } = self;
        let inner = Arc::into_inner(inner)?.into_inner().ok()?;
        let inner = inner.with_tmpdir(tmpdir);
        let Ok(inner) = inner else {
            let e = inner.unwrap_err();
            return Some(Err(e));
        };
        let inner = Arc::new(Mutex::new(inner));
        Some(Ok(Self { inner, handle }))
    }
}

impl Storage for FsStorage {
    type Error = Error;

    fn load(
        &mut self,
        key: StorageKey,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send {
        let inner = Arc::clone(&self.inner);
        let inner_key = key.clone();
        self.handle
            .spawn_blocking(move || inner.lock().unwrap().read(inner_key))
            .map(handle_joinerror)
            .inspect_err(move |e| {
                tracing::error!(err=?e, %key, "error reading chunks from filesystem");
            })
    }

    fn load_range(
        &mut self,
        prefix: StorageKey,
    ) -> impl Future<Output = Result<HashMap<StorageKey, Vec<u8>>, Self::Error>> + Send {
        let inner = Arc::clone(&self.inner);
        let inner_key_prefix = prefix.clone();
        self.handle
            .spawn_blocking(move || inner.lock().unwrap().read_range(inner_key_prefix))
            .map(handle_joinerror)
            .inspect_err(move |e| {
                tracing::error!(err=?e, %prefix, "error reading chunks from filesystem");
            })
    }

    fn put(
        &mut self,
        key: StorageKey,
        value: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let inner = Arc::clone(&self.inner);
        let inner_key = key.clone();
        self.handle
            .spawn_blocking(move || inner.lock().unwrap().write(inner_key, &value))
            .map(handle_joinerror)
            .inspect_err(move |e| {
                tracing::error!(err=?e, %key, "error writing to filesystem");
            })
    }

    fn delete(&mut self, key: StorageKey) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let inner = Arc::clone(&self.inner);
        let inner_key = key.clone();
        self.handle
            .spawn_blocking(move || inner.lock().unwrap().delete(inner_key))
            .map(handle_joinerror)
            .inspect_err(move |e| {
                tracing::error!(err=?e, %key, "error deleting from filesystem");
            })
    }
}

fn handle_joinerror<T>(
    result: Result<Result<T, crate::fs_store::Error>, tokio::task::JoinError>,
) -> Result<T, Error> {
    match result {
        Ok(r) => r.map_err(Error::FsStorage),
        Err(e) => {
            if e.is_panic() {
                std::panic::resume_unwind(e.into_panic());
            } else {
                Err(Error::SpawnBlockingCancelled)
            }
        }
    }
}

mod error {

    pub enum Error {
        SpawnBlockingCancelled,
        FsStorage(crate::fs_store::Error),
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::SpawnBlockingCancelled => write!(f, "spawn_blocking task was cancelled"),
                Self::FsStorage(err) => write!(f, "FsStorage error: {}", err),
            }
        }
    }

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for Error {}
}
