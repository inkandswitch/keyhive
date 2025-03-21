use std::str::FromStr;

use beelay_core::CommitHash;

pub(crate) struct JsCommitHash(CommitHash);

impl serde::Serialize for JsCommitHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for JsCommitHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CommitHash::from_str(&s)
            .map(JsCommitHash)
            .map_err(serde::de::Error::custom)
    }
}

impl From<JsCommitHash> for CommitHash {
    fn from(js_commit_hash: JsCommitHash) -> Self {
        js_commit_hash.0
    }
}

impl From<CommitHash> for JsCommitHash {
    fn from(commit_hash: CommitHash) -> Self {
        JsCommitHash(commit_hash)
    }
}

pub(crate) mod serde_impl {
    use std::str::FromStr;

    use beelay_core::CommitHash;
    use serde::Deserialize;

    pub(crate) fn serialize<S>(commit_hash: &CommitHash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&commit_hash.to_string())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<CommitHash, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CommitHash::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod vec_serde_impl {
    use std::str::FromStr;

    use beelay_core::CommitHash;
    use serde::{Deserialize, Serialize};

    pub(crate) fn serialize<S>(
        commit_hashes: &[CommitHash],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut vec = Vec::with_capacity(commit_hashes.len());
        for commit_hash in commit_hashes {
            vec.push(commit_hash.to_string());
        }
        vec.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CommitHash>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<String>::deserialize(deserializer)?;
        let mut commit_hashes = Vec::with_capacity(vec.len());
        for s in vec {
            commit_hashes.push(CommitHash::from_str(&s).map_err(serde::de::Error::custom)?);
        }
        Ok(commit_hashes)
    }
}
