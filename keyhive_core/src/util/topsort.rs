//! Topological sort with batch-frontier popping.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

/// Variant of Khan's topological sort over nodes of type `T`.
///
/// Nodes are inserted implicitly via [`add_dependency`]. When drained
/// via repeated calls to [`pop_all`], each call returns every node
/// whose predecessors have already been popped, sorted for
/// determinism.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct TopologicalSort<T: Eq + Hash + Clone> {
    /// For each node, the set of its predecessors (nodes that must
    /// come before it).
    deps: HashMap<T, HashSet<T>>,

    /// Reverse index: for each node, the set of nodes that list it as
    /// a predecessor.
    rdeps: HashMap<T, HashSet<T>>,
}

impl<T: Eq + Hash + Clone> TopologicalSort<T> {
    pub fn new() -> Self {
        Self {
            deps: HashMap::new(),
            rdeps: HashMap::new(),
        }
    }

    /// Declare that `before` must be popped before `after`.
    ///
    /// Both nodes are implicitly added if not already present.
    pub fn add_dependency(&mut self, before: T, after: T) {
        self.deps.entry(before.clone()).or_default();
        self.deps
            .entry(after.clone())
            .or_default()
            .insert(before.clone());

        self.rdeps.entry(after.clone()).or_default();
        self.rdeps.entry(before).or_default().insert(after);
    }

    /// Ensure `node` is tracked even if it has no edges.
    pub fn add_node(&mut self, node: T) {
        self.deps.entry(node.clone()).or_default();
        self.rdeps.entry(node).or_default();
    }

    /// Returns `true` when all nodes have been popped.
    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    /// Remove and return the current frontier: every node whose
    /// predecessors have all been popped (i.e., in-degree zero).
    ///
    /// A full drain consists of calling this repeatedly until the
    /// sort [`is_empty`].
    ///
    /// Returns an empty `Vec` if the remaining graph contains a
    /// cycle (or if the sort is already empty).
    pub fn pop_frontier(&mut self) -> Vec<T>
    where
        T: Ord,
    {
        let mut ready: Vec<T> = self
            .deps
            .iter()
            .filter(|(_, preds)| preds.is_empty())
            .map(|(node, _)| node.clone())
            .collect();
        ready.sort();

        for node in &ready {
            self.deps.remove(node);
            if let Some(successors) = self.rdeps.remove(node) {
                for succ in successors {
                    if let Some(pred_set) = self.deps.get_mut(&succ) {
                        pred_set.remove(node);
                    }
                }
            }
        }

        ready
    }
}

impl<T: Eq + Hash + Clone> Default for TopologicalSort<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ── Unit tests ──────────────────────────────────────────────

    #[test]
    fn empty() {
        let mut ts = TopologicalSort::<u32>::new();
        assert!(ts.is_empty());
        assert!(ts.pop_frontier().is_empty());
    }

    #[test]
    fn single_node() {
        let mut ts = TopologicalSort::new();
        ts.add_node(1);
        assert!(!ts.is_empty());
        assert_eq!(ts.pop_frontier(), vec![1]);
        assert!(ts.is_empty());
    }

    #[test]
    fn linear_chain() {
        let mut ts = TopologicalSort::new();
        // 1 -> 2 -> 3
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 3);

        let a = ts.pop_frontier();
        assert_eq!(a, vec![1]);

        let b = ts.pop_frontier();
        assert_eq!(b, vec![2]);

        let c = ts.pop_frontier();
        assert_eq!(c, vec![3]);

        assert!(ts.is_empty());
    }

    #[test]
    fn diamond() {
        let mut ts = TopologicalSort::new();
        // 1 -> 2, 1 -> 3, 2 -> 4, 3 -> 4
        ts.add_dependency(1, 2);
        ts.add_dependency(1, 3);
        ts.add_dependency(2, 4);
        ts.add_dependency(3, 4);

        let mut a = ts.pop_frontier();
        a.sort();
        assert_eq!(a, vec![1]);

        let mut b = ts.pop_frontier();
        b.sort();
        assert_eq!(b, vec![2, 3]);

        let c = ts.pop_frontier();
        assert_eq!(c, vec![4]);

        assert!(ts.is_empty());
    }

    #[test]
    fn cycle_detected() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 1);

        // Both have in-degree 1, neither is ready
        assert!(ts.pop_frontier().is_empty());
        assert!(!ts.is_empty());
    }

    #[test]
    fn isolated_nodes() {
        let mut ts = TopologicalSort::new();
        ts.add_node(1);
        ts.add_node(2);
        ts.add_node(3);

        let mut batch = ts.pop_frontier();
        batch.sort();
        assert_eq!(batch, vec![1, 2, 3]);
        assert!(ts.is_empty());
    }

    #[test]
    fn add_dependency_after_partial_drain() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 3);
        ts.add_dependency(2, 3);

        let mut a = ts.pop_frontier();
        a.sort();
        assert_eq!(a, vec![1, 2]);

        // 3 is now ready but we haven't popped it yet.
        // Add a new edge forcing 3 -> 4.
        ts.add_dependency(3, 4);

        let b = ts.pop_frontier();
        assert_eq!(b, vec![3]);

        let c = ts.pop_frontier();
        assert_eq!(c, vec![4]);

        assert!(ts.is_empty());
    }

    #[test]
    fn duplicate_edges_are_idempotent() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 2);
        ts.add_dependency(1, 2);
        ts.add_dependency(1, 2);

        assert_eq!(ts.pop_frontier(), vec![1]);
        assert_eq!(ts.pop_frontier(), vec![2]);
        assert!(ts.is_empty());
    }

    #[test]
    fn self_loop_is_a_cycle() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 1);

        assert!(ts.pop_frontier().is_empty());
        assert!(!ts.is_empty());
    }

    #[test]
    fn three_node_cycle() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 3);
        ts.add_dependency(3, 1);

        assert!(ts.pop_frontier().is_empty());
        assert!(!ts.is_empty());
    }

    #[test]
    fn mixed_cycle_and_acyclic() {
        // 0 -> 1, 1 -> 2, 2 -> 1 (cycle), 0 -> 3
        let mut ts = TopologicalSort::new();
        ts.add_dependency(0, 1);
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 1); // cycle between 1 and 2
        ts.add_dependency(0, 3);

        // 0 is the only node with in-degree 0
        let first = ts.pop_frontier();
        assert_eq!(first, vec![0]);

        // 3 should be ready, but 1 and 2 are stuck in a cycle
        let second = ts.pop_frontier();
        assert_eq!(second, vec![3]);

        // 1 and 2 remain stuck
        assert!(ts.pop_frontier().is_empty());
        assert!(!ts.is_empty());
    }

    #[test]
    fn wide_fan_out() {
        let mut ts = TopologicalSort::new();
        for i in 1..=100 {
            ts.add_dependency(0, i);
        }

        assert_eq!(ts.pop_frontier(), vec![0]);

        let mut second = ts.pop_frontier();
        second.sort();
        assert_eq!(second, (1..=100).collect::<Vec<_>>());
        assert!(ts.is_empty());
    }

    #[test]
    fn wide_fan_in() {
        let mut ts = TopologicalSort::new();
        for i in 0..100 {
            ts.add_dependency(i, 100);
        }

        let mut first = ts.pop_frontier();
        first.sort();
        assert_eq!(first, (0..100).collect::<Vec<_>>());

        assert_eq!(ts.pop_frontier(), vec![100]);
        assert!(ts.is_empty());
    }

    mod proptests {
        use super::*;
        use std::collections::{BTreeSet, HashMap, HashSet};

        /// Build a DAG from a list of edges on nodes 0..n, filtering
        /// out back-edges (where `from >= to`) to guarantee acyclicity.
        fn build_dag(n: usize, edges: &[(usize, usize)]) -> TopologicalSort<usize> {
            let mut ts = TopologicalSort::new();
            for i in 0..n {
                ts.add_node(i);
            }
            for &(from, to) in edges {
                if from < to && from < n && to < n {
                    ts.add_dependency(from, to);
                }
            }
            ts
        }

        /// Fully drain a topsort and return the flattened output.
        fn drain(ts: &mut TopologicalSort<usize>) -> Vec<usize> {
            let mut output = vec![];
            loop {
                let batch = ts.pop_frontier();
                if batch.is_empty() {
                    break;
                }
                output.extend(batch);
            }
            output
        }

        /// Strategy: generate a DAG with n nodes and random forward edges.
        fn dag_strategy(
            max_nodes: usize,
            max_edges: usize,
        ) -> impl Strategy<Value = (usize, Vec<(usize, usize)>)> {
            (1..=max_nodes).prop_flat_map(move |n| {
                let edge_strat = prop::collection::vec((0..n, 0..n), 0..max_edges);
                (Just(n), edge_strat)
            })
        }

        proptest! {
            /// Every node added to the topsort must appear exactly once
            /// in the drain output (for acyclic graphs).
            #[test]
            fn prop_all_nodes_emitted((n, edges) in dag_strategy(50, 100)) {
                let mut ts = build_dag(n, &edges);
                let output = drain(&mut ts);

                let mut sorted_output = output.clone();
                sorted_output.sort();
                sorted_output.dedup();

                // Every node 0..n appears exactly once
                prop_assert_eq!(sorted_output, (0..n).collect::<Vec<_>>());
                prop_assert!(ts.is_empty());
            }

            /// If there's an edge from A to B, A must appear before B in
            /// the drain output.
            #[test]
            fn prop_respects_dependencies((n, edges) in dag_strategy(50, 100)) {
                let mut ts = build_dag(n, &edges);
                let output = drain(&mut ts);

                // Build position map
                let pos: HashMap<usize, usize> = output
                    .iter()
                    .enumerate()
                    .map(|(i, &node)| (node, i))
                    .collect();

                // Every forward edge must be respected
                for &(from, to) in &edges {
                    if from < to && from < n && to < n {
                        prop_assert!(
                            pos[&from] < pos[&to],
                            "edge {from} -> {to}: pos {from}={} should be < pos {to}={}",
                            pos[&from],
                            pos[&to],
                        );
                    }
                }
            }

            /// Nodes in the same pop_all batch are concurrent: no edge
            /// exists between any pair.
            #[test]
            fn prop_batch_members_are_concurrent((n, edges) in dag_strategy(30, 60)) {
                let mut ts = build_dag(n, &edges);

                // Collect the actual forward edges for lookup
                let edge_set: HashSet<(usize, usize)> = edges
                    .iter()
                    .filter(|&&(from, to)| from < to && from < n && to < n)
                    .copied()
                    .collect();

                loop {
                    let batch = ts.pop_frontier();
                    if batch.is_empty() {
                        break;
                    }
                    // No edge between any pair in the same batch
                    for &a in &batch {
                        for &b in &batch {
                            if a != b {
                                prop_assert!(
                                    !edge_set.contains(&(a, b)),
                                    "batch contains both {a} and {b} but edge {a}->{b} exists",
                                );
                            }
                        }
                    }
                }
            }

            /// Draining the same DAG twice produces the same output
            /// (determinism).
            #[test]
            fn prop_deterministic((n, edges) in dag_strategy(50, 100)) {
                let output1 = drain(&mut build_dag(n, &edges));
                let output2 = drain(&mut build_dag(n, &edges));
                prop_assert_eq!(output1, output2);
            }

            /// Adding isolated nodes (via add_node) doesn't break
            /// existing ordering invariants.
            #[test]
            fn prop_isolated_nodes_dont_affect_order(
                (n, edges) in dag_strategy(30, 60),
                extra_nodes in prop::collection::vec(0..100usize, 0..10),
            ) {
                let mut ts = build_dag(n, &edges);
                let base_output = drain(&mut ts);

                // Same DAG but with extra isolated nodes beyond n
                let mut ts2 = build_dag(n, &edges);
                for &extra in &extra_nodes {
                    let node = n + extra;
                    ts2.add_node(node);
                }
                let extended_output = drain(&mut ts2);

                // The relative order of original nodes 0..n must be preserved
                let original_order: Vec<usize> = extended_output
                    .iter()
                    .filter(|&&x| x < n)
                    .copied()
                    .collect();
                prop_assert_eq!(base_output, original_order);
            }

            /// A topsort with only add_node (no edges) emits everything
            /// in a single batch.
            #[test]
            fn prop_no_edges_single_batch(n in 1..50usize) {
                let mut ts = TopologicalSort::new();
                for i in 0..n {
                    ts.add_node(i);
                }
                let batch = ts.pop_frontier();
                let mut sorted_batch = batch.clone();
                sorted_batch.sort();
                prop_assert_eq!(sorted_batch, (0..n).collect::<Vec<_>>());
                prop_assert!(ts.is_empty());
            }

            /// A linear chain of n nodes produces n singleton batches.
            #[test]
            fn prop_linear_chain_produces_singleton_batches(n in 1..50usize) {
                let mut ts = TopologicalSort::new();
                for i in 0..n.saturating_sub(1) {
                    ts.add_dependency(i, i + 1);
                }
                if n == 1 {
                    ts.add_node(0);
                }
                for i in 0..n {
                    let batch = ts.pop_frontier();
                    prop_assert_eq!(batch, vec![i], "batch at level {}", i);
                }
                prop_assert!(ts.is_empty());
            }

            /// Adding an edge mid-drain between two not-yet-popped nodes
            /// is respected in subsequent pops.
            #[test]
            fn prop_mid_drain_edge_respected(
                (n, edges) in dag_strategy(20, 40),
                extra_from in 0..20usize,
                extra_to in 0..20usize,
            ) {
                // Only valid if both nodes exist and form a forward edge
                if extra_from >= n || extra_to >= n || extra_from >= extra_to {
                    return Ok(());
                }

                let mut ts = build_dag(n, &edges);

                // Drain one batch
                let first_batch: BTreeSet<usize> = ts.pop_frontier().into_iter().collect();

                // If both extra_from and extra_to are still in the topsort
                // (weren't in the first batch), add the edge
                if first_batch.contains(&extra_from) || first_batch.contains(&extra_to) {
                    return Ok(());
                }

                ts.add_dependency(extra_from, extra_to);

                // Drain the rest
                let mut remaining = vec![];
                loop {
                    let batch = ts.pop_frontier();
                    if batch.is_empty() {
                        break;
                    }
                    remaining.extend(batch);
                }

                let pos: HashMap<usize, usize> = remaining
                    .iter()
                    .enumerate()
                    .map(|(i, &node)| (node, i))
                    .collect();

                // The new edge must be respected
                if let (Some(&pf), Some(&pt)) = (pos.get(&extra_from), pos.get(&extra_to)) {
                    prop_assert!(
                        pf < pt,
                        "mid-drain edge {extra_from} -> {extra_to}: pos {extra_from}={pf} should be < pos {extra_to}={pt}",
                    );
                }
            }
        }
    }
}
