use crate::{CommitCategory, DocumentId};

/// Storage key abstraction for a hierarchical key-value store.
///
/// The `StorageKey` represents paths in a hierarchical key-value storage
/// system. The storage system is organized as a prefix-searchable key-value
/// store where keys are sequences of string components separated by '/'
/// characters.
///
/// # Structure
///
/// Storage keys have two main parts:
/// 1. A namespace (required first component)
/// 2. A sequence of string components (optional remaining parts)
///
/// For example: `sedimentrees/doc123/commits` breaks down as:
/// - Namespace: `sedimentrees`
/// - Remaining components: `["doc123", "commits"]`
///
/// # Namespaces
///
/// The system has several predefined namespaces:
/// - `sedimentrees` - For document/commit related data
/// - `blobs` - For binary/blob storage
/// - `auth` - For authentication related data
///
/// Custom namespaces can be created using `Namespace::Other("custom")`.
///
/// # Key Components
///
/// Key components have the following restrictions:
/// - Cannot contain '/' characters
/// - Cannot be empty strings
/// - Must have at least a namespace component
///
/// # Example
/// ```
/// # use beelay_core::storage_key::StorageKey;
/// let key = StorageKey::auth().push("users").push("alice");
/// assert_eq!(key.to_string(), "auth/users/alice");
/// ```
#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct StorageKey {
    namespace: Namespace,
    remaining: Vec<String>,
}

#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Namespace {
    Sedimentrees,
    Blobs,
    Auth,
    Other(String),
}

impl AsRef<str> for Namespace {
    fn as_ref(&self) -> &str {
        match self {
            Namespace::Sedimentrees => "sedimentrees",
            Namespace::Blobs => "blobs",
            Namespace::Auth => "auth",
            Namespace::Other(name) => name,
        }
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Namespace::Blobs => write!(f, "blobs"),
            Namespace::Sedimentrees => write!(f, "sedimentrees"),
            Namespace::Auth => write!(f, "auth"),
            Namespace::Other(name) => write!(f, "{}", name),
        }
    }
}

impl std::fmt::Display for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.namespace)?;
        for part in &self.remaining {
            write!(f, "/{}", part)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl StorageKey {
    /// Creates a storage key for a blob in the blobs namespace.
    ///
    /// # Arguments
    ///
    /// * `blob` - The hash identifying the blob
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::{storage_key::StorageKey, BlobHash};
    /// let blob_hash = BlobHash::new([0; 32]);
    /// let key = StorageKey::blob(blob_hash);
    /// assert_eq!(key.namespace(), "blobs");
    /// ```
    pub fn blob(blob: crate::BlobHash) -> Self {
        StorageKey {
            namespace: Namespace::Blobs,
            remaining: vec![blob.to_string()],
        }
    }

    /// Creates a storage key for a document's root in the sedimentrees namespace.
    ///
    /// # Arguments
    ///
    /// * `doc` - The document identifier
    /// * `category` - The commit category
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::{storage_key::StorageKey, DocumentId, CommitCategory};
    /// let doc_id = DocumentId::new();
    /// let key = StorageKey::sedimentree_root(&doc_id, CommitCategory::Main);
    /// assert_eq!(key.namespace(), "sedimentrees");
    /// ```
    pub fn sedimentree_root(doc: &DocumentId, category: CommitCategory) -> StorageKey {
        StorageKey {
            namespace: Namespace::Sedimentrees,
            remaining: vec![doc.to_string(), category.to_string()],
        }
    }

    /// Creates a storage key in the auth namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let key = StorageKey::auth();
    /// assert_eq!(key.namespace(), "auth");
    /// ```
    pub fn auth() -> StorageKey {
        StorageKey {
            namespace: Namespace::Auth,
            remaining: Vec::new(),
        }
    }

    /// Checks if this key is a prefix of another key.
    ///
    /// A key is considered a prefix if:
    /// - Both keys have the same namespace
    /// - All components of this key match the beginning of the other key's components
    ///
    /// # Arguments
    ///
    /// * `other` - The key to check against
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let base = StorageKey::auth().push("users");
    /// let specific = base.push("alice");
    /// assert!(base.is_prefix_of(&specific));
    /// ```
    pub fn is_prefix_of(&self, other: &StorageKey) -> bool {
        self.namespace == other.namespace
            && self
                .remaining
                .iter()
                .zip(other.remaining.iter())
                .all(|(a, b)| a == b)
    }

    /// Returns the namespace of this storage key as a string slice.
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let key = StorageKey::auth();
    /// assert_eq!(key.namespace(), "auth");
    /// ```
    pub fn namespace(&self) -> &str {
        self.namespace.as_ref()
    }

    /// Returns a slice of the remaining components after the namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let key = StorageKey::auth().push("users").push("alice");
    /// assert_eq!(key.remaining(), &["users", "alice"]);
    /// ```
    pub fn remaining(&self) -> &[String] {
        &self.remaining
    }

    /// Returns an iterator over all components of the key, including the namespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let key = StorageKey::auth().push("users");
    /// let components: Vec<&str> = key.components().collect();
    /// assert_eq!(components, vec!["auth", "users"]);
    /// ```
    pub fn components(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.namespace.as_ref()).chain(self.remaining.iter().map(|s| s.as_str()))
    }

    /// Returns the last component of the key, if any (i.e. this does not include the namespace).
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let key = StorageKey::auth().push("users").push("alice");
    /// assert_eq!(key.name(), Some("alice"));
    /// ```
    pub fn name(&self) -> Option<&str> {
        self.remaining.last().map(|s| s.as_str())
    }

    /// Creates a new storage key by appending a component to this key.
    ///
    /// # Arguments
    ///
    /// * `subcomponent` - The string component to append
    ///
    /// # Example
    ///
    /// ```
    /// # use beelay_core::storage_key::StorageKey;
    /// let base = StorageKey::auth();
    /// let users = base.push("users");
    /// assert_eq!(users.to_string(), "auth/users");
    /// ```
    pub fn push<S: AsRef<str>>(&self, subcomponent: S) -> StorageKey {
        let mut remaining = self.remaining.clone();
        remaining.push(subcomponent.as_ref().to_string());
        StorageKey {
            namespace: self.namespace.clone(),
            remaining,
        }
    }
}

impl TryFrom<Vec<String>> for StorageKey {
    type Error = Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        if value.iter().any(|part| part.contains('/')) {
            return Err(Error::ContainedSlashes);
        }
        if value.is_empty() {
            return Err(Error::Empty);
        }
        let namespace = match value[0].as_str() {
            "sedimentrees" => Namespace::Sedimentrees,
            "blobs" => Namespace::Blobs,
            "auth" => Namespace::Auth,
            other => Namespace::Other(other.to_string()),
        };
        Ok(StorageKey {
            namespace,
            remaining: value[2..].to_vec(),
        })
    }
}

pub enum Error {
    Empty,
    ContainedSlashes,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "attempted to create a storage key from an empty list of strings"
            ),
            Self::ContainedSlashes => write!(f, "storage key components cannot contain slashes"),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Error {}
