//! Topological sort with batch-frontier popping.
//!
//! Replaces the external `topological-sort` crate with a minimal
//! implementation that exposes [`TopologicalSort::pop_all`] for
//! level-by-level draining plus [`TopologicalSort::add_dependency`]
//! for incremental edge insertion (used to force ordering between
//! concurrent revocations).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// A Kahn-style topological sort over nodes of type `T`.
///
/// Nodes are inserted implicitly via [`add_dependency`]. When drained
/// via repeated calls to [`pop_all`], each call returns every node
/// whose predecessors have already been popped, sorted for
/// determinism.
#[derive(Debug)]
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

    /// Remove and return every node whose predecessors have all been
    /// popped (i.e., in-degree zero).
    ///
    /// Returns an empty `Vec` if the remaining graph contains a cycle
    /// (or if the sort is already empty).
    pub fn pop_all(&mut self) -> Vec<T> {
        let ready: Vec<T> = self
            .deps
            .iter()
            .filter(|(_, preds)| preds.is_empty())
            .map(|(node, _)| node.clone())
            .collect();

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

    #[test]
    fn empty() {
        let mut ts = TopologicalSort::<u32>::new();
        assert!(ts.is_empty());
        assert!(ts.pop_all().is_empty());
    }

    #[test]
    fn single_node() {
        let mut ts = TopologicalSort::new();
        ts.add_node(1);
        assert!(!ts.is_empty());
        assert_eq!(ts.pop_all(), vec![1]);
        assert!(ts.is_empty());
    }

    #[test]
    fn linear_chain() {
        let mut ts = TopologicalSort::new();
        // 1 -> 2 -> 3
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 3);

        let a = ts.pop_all();
        assert_eq!(a, vec![1]);

        let b = ts.pop_all();
        assert_eq!(b, vec![2]);

        let c = ts.pop_all();
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

        let mut a = ts.pop_all();
        a.sort();
        assert_eq!(a, vec![1]);

        let mut b = ts.pop_all();
        b.sort();
        assert_eq!(b, vec![2, 3]);

        let c = ts.pop_all();
        assert_eq!(c, vec![4]);

        assert!(ts.is_empty());
    }

    #[test]
    fn cycle_detected() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 2);
        ts.add_dependency(2, 1);

        // Both have in-degree 1, neither is ready
        assert!(ts.pop_all().is_empty());
        assert!(!ts.is_empty());
    }

    #[test]
    fn isolated_nodes() {
        let mut ts = TopologicalSort::new();
        ts.add_node(1);
        ts.add_node(2);
        ts.add_node(3);

        let mut batch = ts.pop_all();
        batch.sort();
        assert_eq!(batch, vec![1, 2, 3]);
        assert!(ts.is_empty());
    }

    #[test]
    fn add_dependency_after_partial_drain() {
        let mut ts = TopologicalSort::new();
        ts.add_dependency(1, 3);
        ts.add_dependency(2, 3);

        let mut a = ts.pop_all();
        a.sort();
        assert_eq!(a, vec![1, 2]);

        // 3 is now ready but we haven't popped it yet.
        // Add a new edge forcing 3 -> 4.
        ts.add_dependency(3, 4);

        let b = ts.pop_all();
        assert_eq!(b, vec![3]);

        let c = ts.pop_all();
        assert_eq!(c, vec![4]);

        assert!(ts.is_empty());
    }
}
