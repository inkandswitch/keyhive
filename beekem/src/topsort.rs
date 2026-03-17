//! Minimal topological sort for `no_std` environments.
//!
//! Replaces the `topological-sort` crate which requires `std`.

use crate::collections::{Map, Set};
use alloc::vec::Vec;
use core::hash::Hash;

/// A topological sort over nodes of type `T`.
pub struct TopologicalSort<T: Eq + Hash + Ord + Clone> {
    /// For each node, the set of nodes it depends on (predecessors).
    deps: Map<T, Set<T>>,
    /// For each node, the set of nodes that depend on it (successors).
    rdeps: Map<T, Set<T>>,
}

impl<T: Eq + Hash + Ord + Clone> TopologicalSort<T> {
    /// Create a new empty topological sort.
    pub fn new() -> Self {
        Self {
            deps: Map::new(),
            rdeps: Map::new(),
        }
    }

    /// Add a dependency: `dependent` depends on `dependency`.
    pub fn add_dependency(&mut self, dependency: T, dependent: T) {
        // Ensure both nodes exist in the dep map
        self.deps.entry(dependency.clone()).or_default();
        self.deps
            .entry(dependent.clone())
            .or_default()
            .insert(dependency.clone());

        // Track reverse deps
        self.rdeps.entry(dependent.clone()).or_default();
        self.rdeps.entry(dependency).or_default().insert(dependent);
    }

    /// Returns whether the sort is empty (all nodes have been popped).
    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    /// Pop all nodes that have no remaining dependencies.
    ///
    /// Returns them sorted for determinism.
    pub fn pop_all(&mut self) -> Vec<T> {
        let ready: Vec<T> = self
            .deps
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(node, _)| node.clone())
            .collect();

        for node in &ready {
            self.deps.remove(node);
            if let Some(dependents) = self.rdeps.remove(node) {
                for dep in dependents {
                    if let Some(dep_set) = self.deps.get_mut(&dep) {
                        dep_set.remove(node);
                    }
                }
            }
        }

        ready
    }
}

impl<T: Eq + Hash + Ord + Clone> Default for TopologicalSort<T> {
    fn default() -> Self {
        Self::new()
    }
}
