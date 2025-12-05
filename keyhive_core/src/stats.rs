use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
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
