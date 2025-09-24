use std::collections::{BTreeMap, BTreeSet, HashSet};

mod blob;
mod commit_dag;
pub mod storage;

pub use blob::*;

pub const TOP_STRATA_LEVEL: Level = Level(2);

#[derive(Clone, Hash, Copy)]
pub struct DocumentId(pub [u8; 32]);

impl std::fmt::Debug for DocumentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DocumentId({})", hex::encode(self.0))
    }
}

#[derive(Debug, Clone)]
pub struct BundleSpec {
    doc: DocumentId,
    start: Digest,
    end: Digest,
    checkpoints: Vec<Digest>,
}

impl BundleSpec {
    pub fn doc(&self) -> DocumentId {
        self.doc
    }
    pub fn start(&self) -> Digest {
        self.start
    }
    pub fn end(&self) -> Digest {
        self.end
    }
    pub fn checkpoints(&self) -> &[Digest] {
        &self.checkpoints
    }
}

#[derive(Clone, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Sedimentree {
    strata: BTreeSet<Stratum>,
    commits: BTreeSet<LooseCommit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SedimentreeSummary {
    strata: BTreeSet<StratumMeta>,
    commits: BTreeSet<LooseCommit>,
}

impl SedimentreeSummary {
    pub fn from_raw(
        strata: BTreeSet<StratumMeta>,
        commits: BTreeSet<LooseCommit>,
    ) -> SedimentreeSummary {
        SedimentreeSummary { strata, commits }
    }

    pub fn strata(&self) -> &BTreeSet<StratumMeta> {
        &self.strata
    }
    pub fn commits(&self) -> &BTreeSet<LooseCommit> {
        &self.commits
    }

    pub fn as_remote_diff(&self) -> RemoteDiff<'_> {
        RemoteDiff {
            remote_strata: self.strata.iter().collect(),
            remote_commits: self.commits.iter().collect(),
            local_strata: Vec::new(),
            local_commits: Vec::new(),
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Level(pub u32);
impl Default for Level {
    fn default() -> Self {
        Self(2)
    }
}

impl<'a> From<&'a Digest> for Level {
    fn from(hash: &'a Digest) -> Self {
        Level(trailing_zeros_in_base(hash.as_bytes(), 10))
    }
}

impl From<Digest> for Level {
    fn from(hash: Digest) -> Self {
        Self::from(&hash)
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Level({})", self.0)
    }
}

impl PartialOrd for Level {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// Flip the ordering so that stratum with a larger number of leading zeros are
// "lower". This is mainly so that the sedimentary rock metaphor holds
impl Ord for Level {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.0.cmp(&other.0) {
            std::cmp::Ordering::Greater => std::cmp::Ordering::Less,
            std::cmp::Ordering::Less => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Equal => std::cmp::Ordering::Equal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Stratum {
    meta: StratumMeta,
    checkpoints: Vec<Digest>,
    digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct StratumMeta {
    start: Digest,
    end: Digest,
    blob: BlobMeta,
}

impl StratumMeta {
    pub fn start(&self) -> Digest {
        self.start
    }
    pub fn end(&self) -> Digest {
        self.end
    }
    pub fn blob(&self) -> BlobMeta {
        self.blob
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LooseCommit {
    digest: Digest,
    parents: Vec<Digest>,
    blob: BlobMeta,
}

pub struct Diff<'a> {
    pub left_missing_strata: Vec<&'a Stratum>,
    pub left_missing_commits: Vec<&'a LooseCommit>,
    pub right_missing_strata: Vec<&'a Stratum>,
    pub right_missing_commits: Vec<&'a LooseCommit>,
}

pub struct RemoteDiff<'a> {
    pub remote_strata: Vec<&'a StratumMeta>,
    pub remote_commits: Vec<&'a LooseCommit>,
    pub local_strata: Vec<&'a Stratum>,
    pub local_commits: Vec<&'a LooseCommit>,
}

impl LooseCommit {
    pub fn new(digest: Digest, parents: Vec<Digest>, blob: BlobMeta) -> Self {
        Self {
            digest,
            parents,
            blob,
        }
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn parents(&self) -> &[Digest] {
        &self.parents
    }

    pub fn blob(&self) -> &BlobMeta {
        &self.blob
    }
}

impl Stratum {
    pub fn new(start: Digest, end: Digest, checkpoints: Vec<Digest>, blob: BlobMeta) -> Self {
        let meta = StratumMeta { start, end, blob };
        let digest = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(start.as_bytes());
            hasher.update(end.as_bytes());
            hasher.update(blob.digest().as_bytes());
            for checkpoint in &checkpoints {
                hasher.update(checkpoint.as_bytes());
            }
            Digest::from(*hasher.finalize().as_bytes())
        };
        Self {
            meta,
            checkpoints,
            digest,
        }
    }

    pub fn from_raw(meta: StratumMeta, checkpoints: Vec<Digest>, digest: Digest) -> Self {
        Stratum {
            meta,
            checkpoints,
            digest,
        }
    }

    pub fn supports(&self, other: &StratumMeta) -> bool {
        if &self.meta == other {
            return true;
        }
        if self.level() >= other.level() {
            return false;
        }
        if self.meta.start == other.start && self.checkpoints.contains(&other.end) {
            return true;
        }
        if self.checkpoints.contains(&other.start) && self.checkpoints.contains(&other.end) {
            return true;
        }
        if self.checkpoints.contains(&other.start) && self.meta.end == other.end {
            return true;
        }
        false
    }

    pub fn supports_block(&self, block_end: Digest) -> bool {
        self.checkpoints.contains(&block_end) || self.meta.end == block_end
    }

    pub fn meta(&self) -> &StratumMeta {
        &self.meta
    }

    pub fn level(&self) -> Level {
        self.meta.level()
    }

    pub fn start(&self) -> Digest {
        self.meta.start
    }

    pub fn end(&self) -> Digest {
        self.meta.end
    }

    pub fn checkpoints(&self) -> &[Digest] {
        &self.checkpoints
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }
}

impl StratumMeta {
    pub fn new(start: Digest, end: Digest, blob: BlobMeta) -> Self {
        Self { start, end, blob }
    }

    pub fn level(&self) -> Level {
        let start_level = trailing_zeros_in_base(self.start.as_bytes(), 10);
        let end_level = trailing_zeros_in_base(self.end.as_bytes(), 10);
        Level(std::cmp::min(start_level, end_level))
    }
}

impl Sedimentree {
    pub fn new(strata: Vec<Stratum>, commits: Vec<LooseCommit>) -> Self {
        Self {
            strata: strata.into_iter().collect(),
            commits: commits.into_iter().collect(),
        }
    }

    pub fn minimal_hash(&self) -> MinimalTreeHash {
        let minimal = self.minimize();
        let mut hashes = minimal
            .strata()
            .flat_map(|s| {
                std::iter::once(s.start())
                    .chain(std::iter::once(s.end()))
                    .chain(s.checkpoints().iter().copied())
            })
            .chain(minimal.commits.iter().map(|c| c.digest()))
            .collect::<Vec<_>>();
        hashes.sort();
        let mut hasher = blake3::Hasher::new();
        for hash in hashes {
            hasher.update(hash.as_bytes());
        }
        MinimalTreeHash(*hasher.finalize().as_bytes())
    }

    // Returns true if the stratum was not already present
    pub fn add_stratum(&mut self, stratum: Stratum) -> bool {
        self.strata.insert(stratum)
    }

    // Returns true if the commit was not already present
    pub fn add_commit(&mut self, commit: LooseCommit) -> bool {
        self.commits.insert(commit)
    }

    pub fn diff<'a>(&'a self, other: &'a Sedimentree) -> Diff<'a> {
        let our_strata = HashSet::<&Stratum>::from_iter(self.strata.iter());
        let their_strata = HashSet::from_iter(other.strata.iter());
        let left_missing_strata = our_strata.difference(&their_strata);
        let right_missing_strata = their_strata.difference(&our_strata);

        let our_commits = HashSet::<&LooseCommit>::from_iter(self.commits.iter());
        let their_commits = HashSet::from_iter(other.commits.iter());
        let left_missing_commits = our_commits.difference(&their_commits);
        let right_missing_commits = their_commits.difference(&our_commits);

        Diff {
            left_missing_strata: left_missing_strata.into_iter().copied().collect(),
            left_missing_commits: left_missing_commits.into_iter().copied().collect(),
            right_missing_strata: right_missing_strata.into_iter().copied().collect(),
            right_missing_commits: right_missing_commits.into_iter().copied().collect(),
        }
    }

    pub fn diff_remote<'a>(&'a self, remote: &'a SedimentreeSummary) -> RemoteDiff<'a> {
        let our_strata_meta =
            HashSet::<&StratumMeta>::from_iter(self.strata.iter().map(|s| &s.meta));
        let their_strata = HashSet::from_iter(remote.strata.iter());
        let local_strata = our_strata_meta.difference(&their_strata).map(|m| {
            self.strata
                .iter()
                .find(|s| s.start() == m.start && s.end() == m.end && s.level() == m.level())
                .unwrap()
        });
        let remote_strata = their_strata.difference(&our_strata_meta);

        let our_commits = HashSet::<&LooseCommit>::from_iter(self.commits.iter());
        let their_commits = HashSet::from_iter(remote.commits.iter());
        let local_commits = our_commits.difference(&their_commits);
        let remote_commits = their_commits.difference(&our_commits);

        RemoteDiff {
            remote_strata: remote_strata.into_iter().copied().collect(),
            remote_commits: remote_commits.into_iter().copied().collect(),
            local_strata: local_strata.into_iter().collect(),
            local_commits: local_commits.into_iter().copied().collect(),
        }
    }

    pub fn strata(&self) -> impl Iterator<Item = &Stratum> {
        self.strata.iter()
    }

    #[allow(dead_code)]
    pub fn loose_commits(&self) -> impl Iterator<Item = &LooseCommit> {
        self.commits.iter()
    }

    pub fn minimize(&self) -> Sedimentree {
        // First sort strata by level, then for each stratum below the lowest
        // level, discard that stratum if it is supported by any of the stratum
        // above it.
        let mut strata = self.strata.iter().collect::<Vec<_>>();
        strata.sort_by(|a, b| a.level().cmp(&b.level()).reverse());

        let mut minimized_strata = Vec::<Stratum>::new();

        for stratum in strata {
            if !minimized_strata
                .iter()
                .any(|existing| existing.supports(&stratum.meta))
            {
                minimized_strata.push(stratum.clone());
            }
        }

        // Now, form a commit graph from the loose commits and simplify it relative to the minimized strata
        let dag = commit_dag::CommitDag::from_commits(self.commits.iter());
        let simplified_dag = dag.simplify(&minimized_strata);

        let commits = self
            .commits
            .iter()
            .filter(|&c| simplified_dag.contains_commit(&c.digest()))
            .cloned()
            .collect();

        Sedimentree::new(minimized_strata, commits)
    }

    pub fn summarize(&self) -> SedimentreeSummary {
        SedimentreeSummary {
            strata: self
                .strata
                .iter()
                .map(|stratum| stratum.meta.clone())
                .collect(),
            commits: self.commits.clone(),
        }
    }

    pub fn heads(&self) -> Vec<Digest> {
        // The heads of a sedimentree are the end hashes of all strata which are
        // not the start of any other stratum or supported by any lower stratum
        // and which do not appear in the loose commit graph, plus the heads of
        // the loose commit graph.
        let minimized = self.minimize();
        let dag = commit_dag::CommitDag::from_commits(minimized.commits.iter());
        let mut heads = Vec::<Digest>::new();
        for stratum in minimized.strata.iter() {
            if !minimized.strata.iter().any(|s| s.end() == stratum.start())
                && !dag.contains_commit(&stratum.end())
            {
                heads.push(stratum.end());
            }
        }
        heads.extend(dag.heads());
        heads
    }

    pub fn into_items(self) -> impl Iterator<Item = CommitOrStratum> {
        self.strata
            .into_iter()
            .map(CommitOrStratum::Stratum)
            .chain(self.commits.into_iter().map(CommitOrStratum::Commit))
    }

    pub fn missing_bundles(&self, doc: DocumentId) -> Vec<BundleSpec> {
        let dag = commit_dag::CommitDag::from_commits(self.commits.iter());
        let mut runs_by_level = BTreeMap::<Level, (Digest, Vec<Digest>)>::new();
        let mut all_bundles = Vec::new();
        for commit_hash in dag.canonical_sequence(self.strata.iter()) {
            let level = Level::from(commit_hash);
            for (run_level, (_start, checkpoints)) in runs_by_level.iter_mut() {
                if run_level < &level {
                    checkpoints.push(commit_hash);
                }
            }
            if level <= crate::TOP_STRATA_LEVEL {
                if let Some((start, checkpoints)) = runs_by_level.remove(&level) {
                    if !self.strata.iter().any(|s| s.supports_block(commit_hash)) {
                        all_bundles.push(BundleSpec {
                            doc,
                            start,
                            end: commit_hash,
                            checkpoints,
                        })
                    }
                } else {
                    runs_by_level.insert(level, (commit_hash, Vec::new()));
                }
            }
        }
        all_bundles
    }

    pub fn as_local_diff(&self) -> RemoteDiff<'_> {
        RemoteDiff {
            remote_strata: Vec::new(),
            remote_commits: Vec::new(),
            local_strata: self.strata.iter().collect(),
            local_commits: self.commits.iter().collect(),
        }
    }
}

pub enum CommitOrStratum {
    Commit(LooseCommit),
    Stratum(Stratum),
}

fn trailing_zeros_in_base(arr: &[u8; 32], base: u32) -> u32 {
    assert!(base > 1, "Base must be greater than 1");
    let bytes = num::BigInt::from_bytes_be(num::bigint::Sign::Plus, arr)
        .to_radix_be(base)
        .1;
    bytes.into_iter().rev().take_while(|&i| i == 0).count() as u32
}

impl std::fmt::Debug for Sedimentree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let strata_summaries = self
            .strata
            .iter()
            .map(|s| {
                format!(
                    "{{level: {}, size_bytes: {}}}",
                    s.level(),
                    s.meta().blob().size_bytes()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        f.debug_struct("Sedimentree")
            .field("strata", &strata_summaries)
            .field("commits", &self.commits.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct MinimalTreeHash([u8; 32]);

impl MinimalTreeHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for MinimalTreeHash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

pub fn has_commit_boundary<I: IntoIterator<Item = D>, D: Into<Digest>>(commits: I) -> bool {
    commits
        .into_iter()
        .any(|digest| Level::from(digest.into()) <= TOP_STRATA_LEVEL)
}

#[cfg(test)]
mod tests {
    use num::Num;

    use super::*;

    fn hash_with_trailing_zeros(
        unstructured: &mut arbitrary::Unstructured<'_>,
        base: u32,
        trailing_zeros: u32,
    ) -> Result<Digest, arbitrary::Error> {
        assert!(base > 1, "Base must be greater than 1");
        assert!(base <= 10, "Base must be less than 10");

        let zero_str = "0".repeat(trailing_zeros as usize);
        let num_digits = (256.0 / (base as f64).log2()).floor() as u64;

        let mut num_str = zero_str;
        num_str.push('1');
        while num_str.len() < num_digits as usize {
            if unstructured.is_empty() {
                return Err(arbitrary::Error::NotEnoughData);
            }
            let digit = unstructured.int_in_range(0..=base - 1)?;
            num_str.push_str(&digit.to_string());
        }
        // reverse the string to get the correct representation
        num_str = num_str.chars().rev().collect();
        let num = num::BigInt::from_str_radix(&num_str, base).unwrap();

        let (_, mut bytes) = num.to_bytes_be();
        if bytes.len() < 32 {
            let mut padded_bytes = vec![0; 32 - bytes.len()];
            padded_bytes.extend(bytes);
            bytes = padded_bytes;
        }
        let byte_arr: [u8; 32] = bytes.try_into().unwrap();
        Ok(Digest::from(byte_arr))
    }

    #[test]
    fn stratum_supports_higher_levels() {
        #[derive(Debug)]
        struct Scenario {
            lower_level: Stratum,
            higher_level: StratumMeta,
        }
        impl<'a> arbitrary::Arbitrary<'a> for Scenario {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                let start_hash = hash_with_trailing_zeros(u, 10, 10)?;
                let lower_end_hash = hash_with_trailing_zeros(u, 10, 10)?;

                #[allow(clippy::enum_variant_names)]
                #[derive(arbitrary::Arbitrary)]
                enum HigherLevelType {
                    StartsAtStartEndsAtCheckpoint,
                    StartsAtCheckpointEndsAtEnd,
                    StartsAtCheckpointEndsAtCheckpoint,
                }

                let higher_start_hash: Digest;
                let higher_end_hash: Digest;
                let mut checkpoints = Vec::<Digest>::arbitrary(u)?;
                let lower_level_type = HigherLevelType::arbitrary(u)?;
                match lower_level_type {
                    HigherLevelType::StartsAtStartEndsAtCheckpoint => {
                        higher_start_hash = start_hash;
                        higher_end_hash = hash_with_trailing_zeros(u, 10, 9)?;
                        checkpoints.push(higher_end_hash);
                    }
                    HigherLevelType::StartsAtCheckpointEndsAtEnd => {
                        higher_start_hash = hash_with_trailing_zeros(u, 10, 9)?;
                        checkpoints.push(higher_start_hash);
                        higher_end_hash = lower_end_hash;
                    }
                    HigherLevelType::StartsAtCheckpointEndsAtCheckpoint => {
                        higher_start_hash = hash_with_trailing_zeros(u, 10, 9)?;
                        higher_end_hash = hash_with_trailing_zeros(u, 10, 9)?;
                        checkpoints.push(higher_start_hash);
                        checkpoints.push(higher_end_hash);
                    }
                };

                let lower_level = Stratum::new(
                    start_hash,
                    lower_end_hash,
                    checkpoints,
                    BlobMeta::arbitrary(u)?,
                );
                let higher_level =
                    StratumMeta::new(higher_start_hash, higher_end_hash, BlobMeta::arbitrary(u)?);

                Ok(Self {
                    lower_level,
                    higher_level,
                })
            }
        }
        bolero::check!().with_arbitrary::<Scenario>().for_each(
            |Scenario {
                 lower_level,
                 higher_level,
             }| {
                assert!(lower_level.supports(higher_level));
            },
        )
    }

    #[test]
    fn minimized_loose_commit_dag_doesnt_change() {
        #[derive(Debug)]
        struct Scenario {
            commits: Vec<super::LooseCommit>,
        }
        impl<'a> arbitrary::Arbitrary<'a> for Scenario {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                let mut frontier: Vec<Digest> = Vec::new();
                let num_commits: u32 = u.int_in_range(1..=20)?;
                let mut result = Vec::with_capacity(num_commits as usize);
                for _ in 0..num_commits {
                    let contents = Vec::<u8>::arbitrary(u)?;
                    let blob = BlobMeta::new(&contents);
                    let hash = crate::Digest::arbitrary(u)?;
                    let mut parents = Vec::new();
                    let mut num_parents = u.int_in_range(0..=frontier.len())?;
                    let mut parent_choices = frontier.iter().collect::<Vec<_>>();
                    while num_parents > 0 {
                        let parent = u.choose(&parent_choices)?;
                        parents.push(**parent);
                        parent_choices
                            .remove(parent_choices.iter().position(|p| p == parent).unwrap());
                        num_parents -= 1;
                    }
                    frontier.retain(|p| !parents.contains(p));
                    frontier.push(hash);
                    result.push(super::LooseCommit {
                        digest: hash,
                        parents,
                        blob,
                    });
                }
                Ok(Scenario { commits: result })
            }
        }
        bolero::check!()
            .with_arbitrary::<Scenario>()
            .for_each(|Scenario { commits }| {
                let tree = super::Sedimentree::new(vec![], commits.clone());
                let minimized = tree.minimize();
                assert_eq!(tree, minimized);
            })
    }
}
