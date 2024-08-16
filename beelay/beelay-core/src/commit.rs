use crate::{hex, parse};

pub use error::InvalidCommitHash;

#[derive(Clone, Copy, Eq, Hash, PartialEq, Ord, PartialOrd, serde::Serialize)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub struct CommitHash([u8; 32]);

impl CommitHash {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn parse(
        input: parse::Input<'_>,
    ) -> Result<(parse::Input<'_>, CommitHash), parse::ParseError> {
        input.with_context("CommitHash", |input| {
            let (input, hash_bytes) = parse::arr::<32>(input)?;
            Ok((input, CommitHash::from(hash_bytes)))
        })
    }

    pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl std::fmt::Display for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        hex::encode(&self.0).fmt(f)
    }
}

impl std::fmt::Debug for CommitHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<[u8; 32]> for CommitHash {
    fn from(value: [u8; 32]) -> Self {
        CommitHash(value)
    }
}

impl<'a> From<&'a [u8; 32]> for CommitHash {
    fn from(value: &'a [u8; 32]) -> Self {
        CommitHash(value.clone())
    }
}

impl std::str::FromStr for CommitHash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(&bytes);
            Ok(CommitHash(id))
        } else {
            Err(hex::FromHexError::InvalidStringLength)
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for CommitHash {
    type Error = error::InvalidCommitHash;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 32 {
            let mut id = [0; 32];
            id.copy_from_slice(value);
            Ok(CommitHash(id))
        } else {
            Err(error::InvalidCommitHash(value.len()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Commit {
    parents: Vec<CommitHash>,
    contents: Vec<u8>,
    hash: CommitHash,
}

#[cfg(test)]
impl<'a> arbitrary::Arbitrary<'a> for Commit {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let parents = Vec::<CommitHash>::arbitrary(u)?;
        let contents = Vec::<u8>::arbitrary(u)?;
        let hash = [u8::arbitrary(u)?; 32];
        Ok(Commit::new(parents, contents, hash.into()))
    }
}

impl Commit {
    pub fn new(parents: Vec<CommitHash>, contents: Vec<u8>, hash: CommitHash) -> Self {
        Commit {
            parents,
            hash,
            contents,
        }
    }

    pub fn parents(&self) -> &[CommitHash] {
        &self.parents
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn hash(&self) -> CommitHash {
        self.hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBundle {
    bundled_commits: Vec<u8>,
    start: CommitHash,
    end: CommitHash,
    checkpoints: Vec<CommitHash>,
}

impl CommitBundle {
    pub fn builder() -> BundleBuilder<UnSet, UnSet, UnSet> {
        BundleBuilder::new()
    }

    pub fn bundled_commits(&self) -> &[u8] {
        &self.bundled_commits
    }

    pub fn start(&self) -> CommitHash {
        self.start
    }

    pub fn end(&self) -> CommitHash {
        self.end
    }

    pub fn checkpoints(&self) -> &[CommitHash] {
        &self.checkpoints
    }
}

pub struct Set<T>(T);
pub struct UnSet;

pub struct BundleBuilder<Start, End, Commits> {
    start: Start,
    end: End,
    commits: Commits,
    checkpoints: Vec<CommitHash>,
}

impl BundleBuilder<UnSet, UnSet, UnSet> {
    fn new() -> Self {
        BundleBuilder {
            start: UnSet,
            end: UnSet,
            commits: UnSet,
            checkpoints: vec![],
        }
    }
}

impl<T, U, V> BundleBuilder<T, U, V> {
    pub fn start(self, start: CommitHash) -> BundleBuilder<Set<CommitHash>, U, V> {
        BundleBuilder {
            start: Set(start),
            end: self.end,
            commits: self.commits,
            checkpoints: self.checkpoints,
        }
    }

    pub fn end(self, end: CommitHash) -> BundleBuilder<T, Set<CommitHash>, V> {
        BundleBuilder {
            start: self.start,
            end: Set(end),
            commits: self.commits,
            checkpoints: self.checkpoints,
        }
    }

    pub fn bundled_commits(self, commits: Vec<u8>) -> BundleBuilder<T, U, Set<Vec<u8>>> {
        BundleBuilder {
            start: self.start,
            end: self.end,
            commits: Set(commits),
            checkpoints: self.checkpoints,
        }
    }

    pub fn checkpoints(self, checkpoints: Vec<CommitHash>) -> Self {
        BundleBuilder {
            start: self.start,
            end: self.end,
            commits: self.commits,
            checkpoints,
        }
    }
}

impl BundleBuilder<Set<CommitHash>, Set<CommitHash>, Set<Vec<u8>>> {
    pub fn build(self) -> CommitBundle {
        CommitBundle {
            start: self.start.0,
            end: self.end.0,
            bundled_commits: self.commits.0,
            checkpoints: self.checkpoints,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOrBundle {
    Commit(Commit),
    Bundle(CommitBundle),
}

mod error {
    pub struct InvalidCommitHash(pub(super) usize);

    impl std::fmt::Display for InvalidCommitHash {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Invalid length {} for commit hash, expected 32", self.0)
        }
    }

    impl std::fmt::Debug for InvalidCommitHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for InvalidCommitHash {}
}
