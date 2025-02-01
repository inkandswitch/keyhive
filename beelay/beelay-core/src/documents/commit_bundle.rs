use super::CommitHash;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitBundle {
    bundled_commits: Vec<u8>,
    start: CommitHash,
    end: CommitHash,
    checkpoints: Vec<CommitHash>,
    hash: CommitHash,
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

    pub fn hash(&self) -> &CommitHash {
        &self.hash
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
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.start.0.as_bytes());
        hasher.update(&self.end.0.as_bytes());
        hasher.update(blake3::hash(&self.commits.0).as_bytes());
        for c in &self.checkpoints {
            hasher.update(&c.as_bytes());
        }
        let hash = hasher.finalize();

        CommitBundle {
            start: self.start.0,
            end: self.end.0,
            bundled_commits: self.commits.0,
            checkpoints: self.checkpoints,
            hash: hash.as_bytes().into(),
        }
    }
}
