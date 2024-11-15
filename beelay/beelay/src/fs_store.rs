use std::{collections::HashMap, fs::File, io::Write, path::Path};

use crate::StorageKey;
pub use error::Error;

/// A database that stores commits in the filesystem
///
/// This store is designed so that concurrent processes can use the same
/// data directory without coordination.
///
/// > Note that this does not implement [`crate::Storage`] directly but rather is
/// > intended to be wrapped in async runtime specific implementations.
#[derive(Debug)]
pub struct FsStore {
    root: std::path::PathBuf,
    tmpdir: std::path::PathBuf,
}

impl FsStore {
    /// Creates a new [`FsStore`] from a [`Path`].
    ///
    /// This will attempt to create the root directory and throw an error if
    /// it does not exist.
    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self, std::io::Error> {
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.into(),
            tmpdir: root.into(),
        })
    }

    /// Overrides the tmpdir directory used for temporary files.
    ///
    /// The default is to use the root directory passed to [`FsStore::open`].
    ///
    /// The tmpdir used must be on the same mount point as the root directory,
    /// otherwise the store will throw an error on writing data.
    ///
    /// # Errors
    ///
    /// This will attempt to create the tmpdir directory and throw an error if
    /// it does not exist.
    pub fn with_tmpdir<P: AsRef<Path>>(self, tmpdir: P) -> Result<Self, std::io::Error> {
        let tmpdir = tmpdir.as_ref();
        std::fs::create_dir_all(tmpdir)?;
        Ok(Self {
            tmpdir: tmpdir.into(),
            ..self
        })
    }

    pub fn read(&self, key: StorageKey) -> Result<Option<Vec<u8>>, Error> {
        let path = self.path(&key);
        if !path.exists() {
            return Ok(None);
        }
        let meta = std::fs::metadata(&path).map_err(|e| Error::read_metadata(path.clone(), e))?;
        if meta.is_dir() {
            return Ok(None);
        }
        std::fs::read(&path)
            .map(Some)
            .map_err(|e| Error::read_file(path, e))
    }

    pub fn read_range(
        &self,
        key_prefix: StorageKey,
    ) -> Result<HashMap<StorageKey, Vec<u8>>, Error> {
        let path = self.path(&key_prefix);
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let meta = std::fs::metadata(&path).map_err(|e| Error::read_metadata(path.clone(), e))?;
        if !meta.is_dir() {
            return Ok(HashMap::new());
        }
        let mut result = HashMap::new();
        let mut dirs_to_process = vec![(key_prefix.clone(), path)];
        while let Some((dir_key, next_dir)) = dirs_to_process.pop() {
            let files =
                std::fs::read_dir(&next_dir).map_err(|e| Error::list_dir(next_dir.clone(), e))?;
            for file in files {
                let entry = file.map_err(|e| Error::list_dir(next_dir.clone(), e))?;
                let meta = entry
                    .metadata()
                    .map_err(|e| Error::read_metadata(entry.path(), e))?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Error::invalid_filename(entry.path()))?;
                if meta.is_dir() {
                    dirs_to_process.push((dir_key.push(name), entry.path()));
                } else {
                    let key = dir_key.push(name);
                    let data = std::fs::read(entry.path())
                        .map_err(|e| Error::read_file(entry.path(), e))?;
                    result.insert(key, data);
                }
            }
        }
        Ok(result)
    }

    pub fn write(&self, key: StorageKey, data: &[u8]) -> Result<(), Error> {
        // first make sure all the intermediate directories exist
        let output_path = self.path(&key);
        std::fs::create_dir_all(output_path.parent().unwrap())
            .map_err(|e| Error::create_dir(output_path.parent().unwrap().into(), e))?;

        let filename = output_path.file_name().unwrap();

        // Write to a temp file and then rename to avoid partial writes
        let temp_dir = tempfile::TempDir::new_in(&self.tmpdir).map_err(Error::create_tempfile)?;
        let temp_save_path = temp_dir.path().join(filename);
        let mut temp_save_file = File::create(&temp_save_path)
            .map_err(|e| Error::write_tempfile(temp_save_path.clone(), e))?;
        temp_save_file
            .write_all(data)
            .map_err(|e| Error::write_tempfile(temp_save_path.clone(), e))?;
        temp_save_file
            .sync_all()
            .map_err(|e| Error::write_tempfile(temp_save_path.clone(), e))?;

        let output_path = self.path(&key);
        std::fs::rename(&temp_save_path, &output_path)
            .map_err(|e| Error::rename_tempfile(temp_save_path, output_path, e))?;

        Ok(())
    }

    pub fn delete(&self, key: StorageKey) -> Result<(), Error> {
        let path = self.path(&key);
        if path.is_dir() {
            tracing::warn!("attempted to delete a directory");
            Ok(())
        } else {
            std::fs::remove_file(&path).map_err(|e| Error::delete(path, e))
        }
    }

    pub fn path(&self, key: &StorageKey) -> std::path::PathBuf {
        let mut path = self.root.clone();
        for component in key.components() {
            path = path.join(component)
        }
        path
    }
}

mod error {

    use std::path::PathBuf;

    pub struct Error(pub(super) ErrorKind);

    impl std::error::Error for Error {}

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let message = self.0.to_string();
            f.debug_struct("Error").field("message", &message).finish()
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

    impl Error {
        pub(super) fn read_metadata(file: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::ReadMetadata(file, error))
        }

        pub(super) fn read_file(file: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::ErrorReadingFile(file, error))
        }

        pub(super) fn list_dir(dir: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::ListDir(dir, error))
        }

        pub(super) fn invalid_filename(file: PathBuf) -> Self {
            Self(ErrorKind::InvalidFilename(file))
        }

        pub(super) fn create_tempfile(error: std::io::Error) -> Self {
            Self(ErrorKind::CreateTempFile(error))
        }

        pub(super) fn create_dir(path: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::CreateDir(path, error))
        }

        pub(super) fn write_tempfile(path: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::WriteTempFile(path, error))
        }

        pub(super) fn rename_tempfile(from: PathBuf, to: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::RenameTempFile(from, to, error))
        }

        pub(super) fn delete(path: PathBuf, error: std::io::Error) -> Self {
            Self(ErrorKind::Delete(path, error))
        }
    }

    #[derive(Debug)]
    pub(super) enum ErrorKind {
        ReadMetadata(PathBuf, std::io::Error),
        ErrorReadingFile(PathBuf, std::io::Error),
        ListDir(PathBuf, std::io::Error),
        InvalidFilename(PathBuf),
        CreateTempFile(std::io::Error),
        CreateDir(PathBuf, std::io::Error),
        WriteTempFile(PathBuf, std::io::Error),
        RenameTempFile(PathBuf, PathBuf, std::io::Error),
        Delete(PathBuf, std::io::Error),
    }

    impl std::fmt::Display for ErrorKind {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ErrorKind::ReadMetadata(file, error) => {
                    write!(f, "Error reading metadata for file {:?}: {}", file, error)
                }
                ErrorKind::ErrorReadingFile(file, error) => {
                    write!(f, "Error reading file {:?}: {}", file, error)
                }
                ErrorKind::ListDir(dir, error) => {
                    write!(f, "Error listing directory {:?}: {}", dir, error)
                }
                ErrorKind::InvalidFilename(file) => {
                    write!(f, "Invalid filename in directory: {:?}", file)
                }
                ErrorKind::CreateTempFile(error) => {
                    write!(f, "Error creating temporary file: {}", error)
                }
                ErrorKind::CreateDir(path, error) => {
                    write!(f, "Error creating directory {:?}: {}", path, error)
                }
                ErrorKind::WriteTempFile(path, error) => {
                    write!(f, "Error writing temporary file {:?}: {}", path, error)
                }
                ErrorKind::RenameTempFile(from, to, error) => {
                    write!(
                        f,
                        "Error renaming temporary file {:?} to {:?}: {}",
                        from, to, error
                    )
                }
                ErrorKind::Delete(path, error) => {
                    write!(f, "Error deleting file {:?}: {}", path, error)
                }
            }
        }
    }
}
