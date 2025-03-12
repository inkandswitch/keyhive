use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::{
    blob::BlobMeta,
    serialization::{parse, Encode, Parse},
    BundleSpec, CommitHash, DocumentId,
};

mod commit_dag;
pub(crate) mod storage;

/// The top most bundle boundary level of a sedimentree, if a commit hash is
/// equal to or lower than this level then it is a checkpoint
pub(crate) const TOP_STRATA_LEVEL: Level = Level(2);

#[derive(Clone, PartialEq, Eq, serde::Serialize, Default, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct Sedimentree {
    strata: BTreeSet<Stratum>,
    commits: BTreeSet<LooseCommit>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Default, Hash)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct SedimentreeSummary {
    strata: BTreeSet<StratumMeta>,
    commits: BTreeSet<LooseCommit>,
}

impl SedimentreeSummary {
    pub(crate) fn as_remote_diff(&self) -> RemoteDiff {
        RemoteDiff {
            remote_strata: self.strata.iter().collect(),
            remote_commits: self.commits.iter().collect(),
            local_strata: Vec::new(),
            local_commits: Vec::new(),
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Level(u32);

impl<'a> From<&'a CommitHash> for Level {
    fn from(hash: &'a CommitHash) -> Self {
        Level(trailing_zeros_in_base(&hash.as_bytes(), 10))
    }
}

impl From<CommitHash> for Level {
    fn from(hash: CommitHash) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct Stratum {
    meta: StratumMeta,
    checkpoints: Vec<CommitHash>,
    hash: CommitHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct StratumMeta {
    start: CommitHash,
    end: CommitHash,
    blob: BlobMeta,
}

impl Encode for StratumMeta {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.start.encode_into(out);
        self.end.encode_into(out);
        self.blob.encode_into(out);
    }
}
impl Parse<'_> for StratumMeta {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("StratumMeta", |input| {
            let (input, start) = CommitHash::parse_in_ctx("start", input)?;
            let (input, end) = CommitHash::parse_in_ctx("end", input)?;
            let (input, blob) = BlobMeta::parse_in_ctx("blob", input)?;
            Ok((input, Self { start, end, blob }))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, PartialOrd, Ord)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct LooseCommit {
    hash: CommitHash,
    parents: Vec<CommitHash>,
    blob: BlobMeta,
}

pub(crate) struct Diff<'a> {
    pub left_missing_strata: Vec<&'a Stratum>,
    pub left_missing_commits: Vec<&'a LooseCommit>,
    pub right_missing_strata: Vec<&'a Stratum>,
    pub right_missing_commits: Vec<&'a LooseCommit>,
}

pub(crate) struct RemoteDiff<'a> {
    pub remote_strata: Vec<&'a StratumMeta>,
    pub remote_commits: Vec<&'a LooseCommit>,
    pub local_strata: Vec<&'a Stratum>,
    pub local_commits: Vec<&'a LooseCommit>,
}

impl LooseCommit {
    pub(crate) fn new(hash: CommitHash, parents: Vec<CommitHash>, blob: BlobMeta) -> Self {
        Self {
            hash,
            parents,
            blob,
        }
    }

    pub(crate) fn hash(&self) -> CommitHash {
        self.hash
    }

    pub(crate) fn parents(&self) -> &[CommitHash] {
        &self.parents
    }

    pub(crate) fn blob(&self) -> &BlobMeta {
        &self.blob
    }
}

impl Encode for LooseCommit {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.hash.encode_into(out);
        self.parents.encode_into(out);
        self.blob.encode_into(out);
    }
}

impl Parse<'_> for LooseCommit {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("LooseCommit", |input| {
            let (input, hash) = CommitHash::parse_in_ctx("hash", input)?;
            let (input, parents) = Vec::<CommitHash>::parse_in_ctx("parents", input)?;
            let (input, blob) = BlobMeta::parse_in_ctx("blob", input)?;
            Ok((
                input,
                Self {
                    hash,
                    parents,
                    blob,
                },
            ))
        })
    }
}

impl Stratum {
    pub(crate) fn new(
        start: CommitHash,
        end: CommitHash,
        checkpoints: Vec<CommitHash>,
        blob: BlobMeta,
    ) -> Self {
        let meta = StratumMeta { start, end, blob };
        let hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&start.as_bytes());
            hasher.update(&end.as_bytes());
            hasher.update(blob.hash().as_bytes());
            for checkpoint in &checkpoints {
                hasher.update(&checkpoint.as_bytes());
            }
            CommitHash::from(*hasher.finalize().as_bytes())
        };
        Self {
            meta,
            checkpoints,
            hash,
        }
    }

    pub(crate) fn supports(&self, other: &StratumMeta) -> bool {
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

    pub(crate) fn supports_block(&self, block_end: CommitHash) -> bool {
        self.checkpoints.contains(&block_end) || self.meta.end == block_end
    }

    pub(crate) fn meta(&self) -> &StratumMeta {
        &self.meta
    }

    pub(crate) fn level(&self) -> Level {
        self.meta.level()
    }

    pub(crate) fn start(&self) -> CommitHash {
        self.meta.start
    }

    pub(crate) fn end(&self) -> CommitHash {
        self.meta.end
    }

    pub(crate) fn checkpoints(&self) -> &[CommitHash] {
        &self.checkpoints
    }

    pub(crate) fn hash(&self) -> CommitHash {
        self.hash
    }
}

impl Encode for Stratum {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.meta.start.encode_into(out);
        self.meta.end.encode_into(out);
        self.meta.blob.encode_into(out);
        self.checkpoints.encode_into(out);
        self.hash.encode_into(out);
    }
}

impl Parse<'_> for Stratum {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("Stratum", |input| {
            let (input, start) = CommitHash::parse_in_ctx("start", input)?;
            let (input, end) = CommitHash::parse_in_ctx("end", input)?;
            let (input, blob) = BlobMeta::parse_in_ctx("blob", input)?;
            let (input, checkpoints) = Vec::<CommitHash>::parse_in_ctx("checkpoints", input)?;
            let (input, hash) = CommitHash::parse_in_ctx("hash", input)?;
            Ok((
                input,
                Self {
                    meta: StratumMeta { start, end, blob },
                    checkpoints,
                    hash,
                },
            ))
        })
    }
}

impl StratumMeta {
    #[cfg(test)]
    pub(crate) fn new(start: CommitHash, end: CommitHash, blob: BlobMeta) -> Self {
        Self { start, end, blob }
    }

    pub(crate) fn level(&self) -> Level {
        let start_level = trailing_zeros_in_base(&self.start.as_bytes(), 10);
        let end_level = trailing_zeros_in_base(&self.end.as_bytes(), 10);
        Level(std::cmp::min(start_level, end_level))
    }

    pub(crate) fn blob(&self) -> &BlobMeta {
        &self.blob
    }
}

impl Sedimentree {
    pub(crate) fn new(strata: Vec<Stratum>, commits: Vec<LooseCommit>) -> Self {
        Self {
            strata: strata.into_iter().collect(),
            commits: commits.into_iter().collect(),
        }
    }

    pub(crate) fn minimal_hash(&self) -> MinimalTreeHash {
        let minimal = self.minimize();
        let mut hashes = minimal
            .strata()
            .flat_map(|s| {
                std::iter::once(s.start())
                    .chain(std::iter::once(s.end()))
                    .chain(s.checkpoints().iter().copied())
            })
            .chain(minimal.commits.iter().map(|c| c.hash()))
            .collect::<Vec<_>>();
        hashes.sort();
        let mut hasher = blake3::Hasher::new();
        for hash in hashes {
            hasher.update(&hash.as_bytes());
        }
        MinimalTreeHash(*hasher.finalize().as_bytes())
    }

    // Returns true if the stratum was not already present
    pub(crate) fn add_stratum(&mut self, stratum: Stratum) -> bool {
        self.strata.insert(stratum)
    }

    // Returns true if the commit was not already present
    pub(crate) fn add_commit(&mut self, commit: LooseCommit) -> bool {
        self.commits.insert(commit)
    }

    pub(crate) fn diff<'a>(&'a self, other: &'a Sedimentree) -> Diff<'a> {
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

    pub(crate) fn diff_remote<'a>(&'a self, remote: &'a SedimentreeSummary) -> RemoteDiff<'a> {
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

    pub(crate) fn strata(&self) -> impl Iterator<Item = &Stratum> {
        self.strata.iter()
    }

    #[allow(dead_code)]
    pub(crate) fn loose_commits(&self) -> impl Iterator<Item = &LooseCommit> {
        self.commits.iter()
    }

    pub(crate) fn minimize(&self) -> Sedimentree {
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
            .filter(|&c| simplified_dag.contains_commit(&c.hash()))
            .cloned()
            .collect();

        Sedimentree::new(minimized_strata, commits)
    }

    pub(crate) fn summarize(&self) -> SedimentreeSummary {
        SedimentreeSummary {
            strata: self
                .strata
                .iter()
                .map(|stratum| stratum.meta.clone())
                .collect(),
            commits: self.commits.clone(),
        }
    }

    pub(crate) fn heads(&self) -> Vec<CommitHash> {
        // The heads of a sedimentree are the end hashes of all strata which are
        // not the start of any other stratum or supported by any lower stratum
        // and which do not appear in the loose commit graph, plus the heads of
        // the loose commit graph.
        let minimized = self.minimize();
        let dag = commit_dag::CommitDag::from_commits(minimized.commits.iter());
        let mut heads = Vec::<CommitHash>::new();
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

    pub(crate) fn into_items(self) -> impl Iterator<Item = CommitOrStratum> {
        self.strata
            .into_iter()
            .map(CommitOrStratum::Stratum)
            .chain(self.commits.into_iter().map(CommitOrStratum::Commit))
    }

    pub(crate) fn missing_bundles(&self, doc: DocumentId) -> Vec<BundleSpec> {
        let dag = commit_dag::CommitDag::from_commits(self.commits.iter());
        let mut runs_by_level = BTreeMap::<Level, (CommitHash, Vec<CommitHash>)>::new();
        let mut all_bundles = Vec::new();
        for commit_hash in dag.canonical_sequence(self.strata.iter()) {
            let level = Level::from(commit_hash);
            for (run_level, (_start, checkpoints)) in runs_by_level.iter_mut() {
                if run_level < &level {
                    checkpoints.push(commit_hash);
                }
            }
            if level <= TOP_STRATA_LEVEL {
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

    pub(crate) fn as_local_diff(&self) -> RemoteDiff {
        RemoteDiff {
            remote_strata: Vec::new(),
            remote_commits: Vec::new(),
            local_strata: self.strata.iter().collect(),
            local_commits: self.commits.iter().collect(),
        }
    }
}

impl Parse<'_> for SedimentreeSummary {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        input.parse_in_ctx("SedimentreeSummary", |input| {
            let (input, strata) = Vec::<StratumMeta>::parse_in_ctx("strata", input)?;
            let (input, commits) = Vec::<LooseCommit>::parse_in_ctx("commits", input)?;
            Ok((
                input,
                Self {
                    strata: strata.into_iter().collect(),
                    commits: commits.into_iter().collect(),
                },
            ))
        })
    }
}

impl Encode for SedimentreeSummary {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.strata
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .encode_into(out);
        self.commits
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .encode_into(out);
    }
}

pub(crate) enum CommitOrStratum {
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
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
pub(crate) struct MinimalTreeHash([u8; 32]);

impl MinimalTreeHash {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for MinimalTreeHash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use num::Num;

    use super::{Stratum, StratumMeta};
    use crate::{
        blob::BlobMeta,
        serialization::{parse, Encode, Parse},
        CommitHash,
    };

    pub(crate) fn hash_with_trailing_zeros(
        unstructured: &mut arbitrary::Unstructured<'_>,
        base: u32,
        trailing_zeros: u32,
    ) -> Result<CommitHash, arbitrary::Error> {
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
        Ok(CommitHash::from(byte_arr))
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

                let higher_start_hash: CommitHash;
                let higher_end_hash: CommitHash;
                let mut checkpoints = Vec::<CommitHash>::arbitrary(u)?;
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
    fn loose_commit_encoding_roundtrip() {
        bolero::check!()
            .with_arbitrary::<super::LooseCommit>()
            .for_each(|c| {
                let encoded = c.encode();
                let (_, decoded) = super::LooseCommit::parse(parse::Input::new(&encoded)).unwrap();
                assert_eq!(c, &decoded);
            });
    }

    #[test]
    fn minimized_loose_commit_dag_doesnt_change() {
        #[derive(Debug)]
        struct Scenario {
            commits: Vec<super::LooseCommit>,
        }
        impl<'a> arbitrary::Arbitrary<'a> for Scenario {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                let mut frontier: Vec<CommitHash> = Vec::new();
                let num_commits: u32 = u.int_in_range(1..=20)?;
                let mut result = Vec::with_capacity(num_commits as usize);
                for _ in 0..num_commits {
                    let contents = Vec::<u8>::arbitrary(u)?;
                    let blob = BlobMeta::new(&contents);
                    let hash = crate::CommitHash::arbitrary(u)?;
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
                        hash,
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
