use std::collections::{HashMap, HashSet};

use beelay::{CommitBundle, CommitHash, CommitOrBundle};
use petgraph::Direction;

pub(crate) struct Doc {
    commit_graph: petgraph::Graph<SimpleCommit, (), petgraph::Directed>,
    nodes: HashMap<CommitHash, petgraph::graph::NodeIndex>,
}

impl Doc {
    pub(crate) fn new() -> Self {
        Doc {
            commit_graph: petgraph::Graph::new(),
            nodes: HashMap::new(),
        }
    }

    pub(crate) fn load(chunks: Vec<CommitOrBundle>) -> Self {
        let mut commits = HashSet::new();
        for chunk in chunks {
            match chunk {
                CommitOrBundle::Bundle(b) => {
                    let bundled = BundledCounts::decode(b.bundled_commits());
                    commits.extend(bundled.inflate());
                }
                CommitOrBundle::Commit(c) => {
                    commits.insert(SimpleCommit::decode(c.contents()));
                }
            }
        }
        let mut graph = petgraph::Graph::new();
        let mut nodes = HashMap::new();
        for commit in &commits {
            let node = graph.add_node(commit.clone());
            nodes.insert(commit.hash(), node);
        }
        for commit in commits {
            let node = nodes.get(&commit.hash()).unwrap();
            for parent in commit.parents {
                let parent_node = nodes.get(&parent).unwrap();
                graph.add_edge(*parent_node, *node, ());
            }
        }
        Self {
            commit_graph: graph,
            nodes,
        }
    }

    pub(crate) fn value(&self) -> usize {
        if self.commit_graph.node_count() == 0 {
            0
        } else {
            let root = self
                .commit_graph
                .externals(Direction::Incoming)
                .next()
                .unwrap();
            let mut dfs = petgraph::visit::Dfs::new(&self.commit_graph, root);
            let mut count = 0;
            while let Some(node) = dfs.next(&self.commit_graph) {
                count += self.commit_graph[node].value();
            }
            count
        }
    }

    pub(crate) fn increment(&mut self, amount: usize) -> SimpleCommit {
        let heads = self
            .commit_graph
            .externals(Direction::Outgoing)
            .map(|c| {
                let commit = &self.commit_graph[c];
                (c, commit.hash())
            })
            .collect::<Vec<_>>();
        let parents = heads.iter().map(|(_, hash)| *hash).collect();
        let parent_idxs = heads.iter().map(|(idx, _)| *idx).collect::<Vec<_>>();
        let commit = SimpleCommit {
            parents,
            counter: amount,
        };
        let node_idx = self.commit_graph.add_node(commit.clone());
        for parent_idx in parent_idxs {
            self.commit_graph.add_edge(parent_idx, node_idx, ());
        }
        self.nodes.insert(commit.hash(), node_idx);
        commit
    }

    pub(crate) fn bundle(
        &self,
        start_hash: CommitHash,
        end_hash: CommitHash,
        checkpoints: Vec<CommitHash>,
    ) -> CommitBundle {
        let start_idx = *self.nodes.get(&start_hash).unwrap();
        let start = self.commit_graph[start_idx].clone();
        let end_idx = *self.nodes.get(&end_hash).unwrap();

        let mut bundle = Vec::new();
        let mut to_process = vec![(start_idx, start)];
        let mut started = false;
        while let Some((next_idx, commit)) = to_process.pop() {
            let mut parents = self
                .commit_graph
                .neighbors_directed(next_idx, Direction::Incoming)
                .map(|p| (p, self.commit_graph[p].clone()))
                .collect::<Vec<_>>();
            parents.sort_by_key(|(_idx, commit)| commit.hash());
            to_process.extend(parents);
            if commit.hash() == start_hash {
                started = true;
            }
            if started {
                bundle.push(commit.clone());
            }
            if commit.hash() == end_hash {
                break;
            }
        }
        bundle.reverse();
        let mut bundle_parents = self
            .commit_graph
            .neighbors_directed(end_idx, Direction::Incoming)
            .map(|idx| self.commit_graph[idx].hash())
            .collect::<Vec<_>>();
        bundle_parents.sort();

        let hash_to_index = bundle
            .iter()
            .enumerate()
            .map(|(i, c)| (c.hash(), i))
            .collect::<HashMap<_, _>>();

        let parents = bundle.iter().map(|c| {
            c.parents
                .iter()
                .map(|p| {
                    hash_to_index
                        .get(p)
                        .copied()
                        .map(CommitRef::InThisBundle)
                        .unwrap_or_else(|| CommitRef::Hash(*p))
                })
                .collect()
        });

        let bundle = BundledCounts {
            parents: bundle_parents,
            parent_refs: parents.collect(),
            counts: bundle.iter().map(|c| c.value() as u64).collect(),
            start: start_hash,
            end: end_hash,
        };
        CommitBundle::builder()
            .start(start_hash)
            .end(end_hash)
            .bundled_commits(bundle.encode())
            .checkpoints(checkpoints)
            .build()
    }

    pub(crate) fn size(&self) -> usize {
        self.nodes
            .values()
            .map(|idx| self.commit_graph[*idx].encode().len())
            .sum()
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) struct SimpleCommit {
    pub parents: Vec<CommitHash>,
    counter: usize,
}

impl SimpleCommit {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&(self.parents.len() as u64).to_be_bytes());
        for parent in &self.parents {
            out.extend(parent.as_bytes());
        }
        out
    }

    fn decode(buf: &[u8]) -> Self {
        let counter = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]) as usize;
        let parent_count = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]) as usize;
        let mut parents = Vec::new();
        for i in 0..parent_count {
            let start = 16 + i * 32;
            let end = start + 32;
            let mut parent = [0; 32];
            parent.copy_from_slice(&buf[start..end]);
            parents.push(CommitHash::from(parent));
        }
        SimpleCommit { parents, counter }
    }

    pub(crate) fn hash(&self) -> CommitHash {
        blake3::hash(&self.encode()).as_bytes().into()
    }

    pub(crate) fn value(&self) -> usize {
        self.counter
    }
}

#[derive(Debug)]
enum CommitRef {
    InThisBundle(usize),
    Hash(CommitHash),
}

#[derive(Debug)]
struct BundledCounts {
    parents: Vec<CommitHash>,
    counts: Vec<u64>,
    parent_refs: Vec<Vec<CommitRef>>,
    start: CommitHash,
    end: CommitHash,
}

macro_rules! from_be_bytes {
    ($buf:expr, $offset:expr) => {
        u64::from_be_bytes([
            $buf[$offset],
            $buf[$offset + 1],
            $buf[$offset + 2],
            $buf[$offset + 3],
            $buf[$offset + 4],
            $buf[$offset + 5],
            $buf[$offset + 6],
            $buf[$offset + 7],
        ])
    };
}

impl BundledCounts {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.start.as_bytes());
        out.extend_from_slice(&self.end.as_bytes());
        out.extend_from_slice(&(self.parents.len() as u64).to_be_bytes());
        for parent in &self.parents {
            out.extend_from_slice(&parent.as_bytes());
        }
        out.extend_from_slice(&(self.counts.len() as u64).to_be_bytes());
        for count in &self.counts {
            out.extend_from_slice(&(count.to_be_bytes()));
        }
        out.extend_from_slice(&(self.parent_refs.len() as u64).to_be_bytes());
        for parent_ref in &self.parent_refs {
            out.extend_from_slice(&(parent_ref.len() as u64).to_be_bytes());
            for pr in parent_ref {
                match pr {
                    CommitRef::InThisBundle(idx) => {
                        out.push(0);
                        out.extend_from_slice(&(idx.to_be_bytes()));
                    }
                    CommitRef::Hash(hash) => {
                        out.push(1);
                        out.extend_from_slice(&hash.as_bytes());
                    }
                }
            }
        }
        out
    }

    fn decode(buf: &[u8]) -> Self {
        let mut offset = 0;
        let start = CommitHash::try_from(&buf[offset..offset + 32]).unwrap();
        offset += 32;
        let end = CommitHash::try_from(&buf[offset..offset + 32]).unwrap();
        offset += 32;
        let parent_count = from_be_bytes!(buf, offset);
        offset += 8;
        let mut parents = Vec::new();
        for _ in 0..parent_count {
            let parent = CommitHash::try_from(&buf[offset..offset + 32]).unwrap();
            offset += 32;
            parents.push(parent);
        }
        let count_count = from_be_bytes!(buf, offset);
        offset += 8;
        let mut counts = Vec::new();
        for _ in 0..count_count {
            let c = from_be_bytes!(buf, offset);
            offset += 8;
            counts.push(c);
        }
        let parent_ref_count = from_be_bytes!(buf, offset);
        offset += 8;
        let mut parent_refs = Vec::new();
        for _ in 0..parent_ref_count {
            let parent_ref_len = from_be_bytes!(buf, offset);
            offset += 8;
            let mut parent_ref = Vec::new();
            for _ in 0..parent_ref_len {
                let pr_type = buf[offset];
                offset += 1;
                let pr = match pr_type {
                    0 => {
                        let idx = from_be_bytes!(buf, offset);
                        offset += 8;
                        CommitRef::InThisBundle(idx as usize)
                    }
                    1 => {
                        let hash = CommitHash::try_from(&buf[offset..offset + 32]).unwrap();
                        offset += 32;
                        CommitRef::Hash(hash)
                    }
                    _ => panic!("Invalid commit ref type"),
                };
                parent_ref.push(pr);
            }
            parent_refs.push(parent_ref);
        }
        BundledCounts {
            start,
            end,
            parents,
            counts,
            parent_refs,
        }
    }

    fn inflate(&self) -> Vec<SimpleCommit> {
        let mut commits: Vec<SimpleCommit> = Vec::new();
        for i in 0..self.counts.len() {
            let count = self.counts[i];
            let mut parents: Vec<CommitHash> = Vec::new();
            for parent_ref in &self.parent_refs[i] {
                match parent_ref {
                    CommitRef::InThisBundle(idx) => {
                        parents.push(commits[*idx].hash());
                    }
                    CommitRef::Hash(hash) => {
                        parents.push(*hash);
                    }
                }
            }
            let commit = SimpleCommit {
                parents,
                counter: count as usize,
            };
            commits.push(commit);
        }
        commits
    }
}
