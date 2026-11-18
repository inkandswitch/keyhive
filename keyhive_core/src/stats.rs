#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Stats {
    pub individuals: u64,
    pub groups: u64,
    pub docs: u64,
    pub delegations: u64,
    pub revocations: u64,
    pub prekeys_expanded: u64,
    pub prekey_rotations: u64,
    pub cgka_operations: u64,
    pub active_prekey_count: u64,
    pub pending_prekeys_expanded: u64,
    pub pending_prekeys_expanded_by_active: u64,
    pub pending_prekey_rotated: u64,
    pub pending_prekey_rotated_by_active: u64,
    pub pending_cgka_operation: u64,
    pub pending_cgka_operation_by_active: u64,
    pub pending_delegated: u64,
    pub pending_delegated_by_active: u64,
    pub pending_revoked: u64,
    pub pending_revoked_by_active: u64,
}

impl Stats {
    /// How many ops this instance has applied, including delegations,
    /// revocations, prekey expansions, prekey rotations, and CGKA operations.
    pub fn total_ops(&self) -> u64 {
        self.delegations
            + self.revocations
            + self.prekeys_expanded
            + self.prekey_rotations
            + self.cgka_operations
    }

    /// How many events this instance holds but cannot yet apply.
    pub fn pending_total(&self) -> u64 {
        self.pending_prekeys_expanded
            + self.pending_prekey_rotated
            + self.pending_cgka_operation
            + self.pending_delegated
            + self.pending_revoked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_ops_adds_the_five_applied_op_counts() {
        let stats = Stats {
            individuals: 100,
            groups: 101,
            docs: 102,
            delegations: 1,
            revocations: 2,
            prekeys_expanded: 3,
            prekey_rotations: 4,
            cgka_operations: 5,
            active_prekey_count: 103,
            pending_prekeys_expanded: 104,
            pending_prekeys_expanded_by_active: 105,
            pending_prekey_rotated: 106,
            pending_prekey_rotated_by_active: 107,
            pending_cgka_operation: 108,
            pending_cgka_operation_by_active: 109,
            pending_delegated: 110,
            pending_delegated_by_active: 111,
            pending_revoked: 112,
            pending_revoked_by_active: 113,
        };
        assert_eq!(stats.total_ops(), 15);
    }
}
