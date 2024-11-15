// Storage layout:
//
// <dag_id>/commits/<category>/<commit hash>

use crate::{CommitCategory, DocumentId};

#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct StorageKey {
    namespace: Namespace,
    remaining: Vec<String>,
}

#[derive(Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum Namespace {
    Dags,
    Sedimentrees,
    Blobs,
    Other(String),
}

impl AsRef<str> for Namespace {
    fn as_ref(&self) -> &str {
        match self {
            Namespace::Dags => "dags",
            Namespace::Sedimentrees => "sedimentrees",
            Namespace::Blobs => "blobs",
            Namespace::Other(name) => name,
        }
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Namespace::Dags => write!(f, "dags"),
            Namespace::Blobs => write!(f, "blobs"),
            Namespace::Sedimentrees => write!(f, "sedimentrees"),
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
    pub fn blob(blob: crate::BlobHash) -> Self {
        StorageKey {
            namespace: Namespace::Blobs,
            remaining: vec![blob.to_string()],
        }
    }

    pub fn sedimentree_root(doc: &DocumentId, category: CommitCategory) -> StorageKey {
        StorageKey {
            namespace: Namespace::Sedimentrees,
            remaining: vec![doc.to_string(), category.to_string()],
        }
    }

    pub fn is_prefix_of(&self, other: &StorageKey) -> bool {
        self.namespace == other.namespace
            && self
                .remaining
                .iter()
                .zip(other.remaining.iter())
                .all(|(a, b)| a == b)
    }

    pub fn namespace(&self) -> &str {
        self.namespace.as_ref()
    }

    pub fn remaining(&self) -> &[String] {
        &self.remaining
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.namespace.as_ref()).chain(self.remaining.iter().map(|s| s.as_str()))
    }

    pub fn name(&self) -> Option<&str> {
        self.remaining.last().map(|s| s.as_str())
    }

    pub fn with_subcomponent<S: AsRef<str>>(&self, subcomponent: S) -> StorageKey {
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
            "dags" => Namespace::Dags,
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
