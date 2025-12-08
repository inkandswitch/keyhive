use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Serialize, Deserialize)]
pub struct Stats {
    pub individuals: u64,
    pub groups: u64,
    pub docs: u64,
    pub delegations: u64,
    pub revocations: u64,
    pub active_prekey_count: u64,
}
