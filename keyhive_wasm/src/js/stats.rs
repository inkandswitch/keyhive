use keyhive_core::stats::Stats;
use serde::{Deserialize, Serialize};
use std::fmt;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(js_name = Stats)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsStats(pub(crate) Stats);

impl fmt::Display for JsStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stats {{ individuals: {}, groups: {}, docs: {}, delegations: {}, revocations: {}, prekeys_expanded: {}, prekey_rotations: {}, cgka_operations: {}, active_prekey_count: {}, pending_prekeys_expanded: {}, pending_prekeys_expanded_by_active: {}, pending_prekey_rotated: {}, pending_prekey_rotated_by_active: {}, pending_cgka_operation: {}, pending_cgka_operation_by_active: {}, pending_delegated: {}, pending_delegated_by_active: {}, pending_revoked: {}, pending_revoked_by_active: {} }}",
            self.0.individuals,
            self.0.groups,
            self.0.docs,
            self.0.delegations,
            self.0.revocations,
            self.0.prekeys_expanded,
            self.0.prekey_rotations,
            self.0.cgka_operations,
            self.0.active_prekey_count,
            self.0.pending_prekeys_expanded,
            self.0.pending_prekeys_expanded_by_active,
            self.0.pending_prekey_rotated,
            self.0.pending_prekey_rotated_by_active,
            self.0.pending_cgka_operation,
            self.0.pending_cgka_operation_by_active,
            self.0.pending_delegated,
            self.0.pending_delegated_by_active,
            self.0.pending_revoked,
            self.0.pending_revoked_by_active
        )
    }
}

#[wasm_bindgen(js_class = Stats)]
impl JsStats {
    #[wasm_bindgen(getter)]
    pub fn individuals(&self) -> u64 {
        self.0.individuals
    }

    #[wasm_bindgen(getter)]
    pub fn groups(&self) -> u64 {
        self.0.groups
    }

    #[wasm_bindgen(getter)]
    pub fn docs(&self) -> u64 {
        self.0.docs
    }

    #[wasm_bindgen(getter)]
    pub fn delegations(&self) -> u64 {
        self.0.delegations
    }

    #[wasm_bindgen(getter)]
    pub fn revocations(&self) -> u64 {
        self.0.revocations
    }

    #[wasm_bindgen(getter, js_name = prekeysExpanded)]
    pub fn prekeys_expanded(&self) -> u64 {
        self.0.prekeys_expanded
    }

    #[wasm_bindgen(getter, js_name = prekeyRotations)]
    pub fn prekey_rotations(&self) -> u64 {
        self.0.prekey_rotations
    }

    #[wasm_bindgen(getter, js_name = cgkaOperations)]
    pub fn cgka_operations(&self) -> u64 {
        self.0.cgka_operations
    }

    #[wasm_bindgen(getter, js_name = activePrekeyCount)]
    pub fn active_prekey_count(&self) -> u64 {
        self.0.active_prekey_count
    }

    #[wasm_bindgen(getter, js_name = pendingPrekeysExpanded)]
    pub fn pending_prekeys_expanded(&self) -> u64 {
        self.0.pending_prekeys_expanded
    }

    #[wasm_bindgen(getter, js_name = pendingPrekeysExpandedByActive)]
    pub fn pending_prekeys_expanded_by_active(&self) -> u64 {
        self.0.pending_prekeys_expanded_by_active
    }

    #[wasm_bindgen(getter, js_name = pendingPrekeyRotated)]
    pub fn pending_prekey_rotated(&self) -> u64 {
        self.0.pending_prekey_rotated
    }

    #[wasm_bindgen(getter, js_name = pendingPrekeyRotatedByActive)]
    pub fn pending_prekey_rotated_by_active(&self) -> u64 {
        self.0.pending_prekey_rotated_by_active
    }

    #[wasm_bindgen(getter, js_name = pendingCgkaOperation)]
    pub fn pending_cgka_operation(&self) -> u64 {
        self.0.pending_cgka_operation
    }

    #[wasm_bindgen(getter, js_name = pendingCgkaOperationByActive)]
    pub fn pending_cgka_operation_by_active(&self) -> u64 {
        self.0.pending_cgka_operation_by_active
    }

    #[wasm_bindgen(getter, js_name = pendingDelegated)]
    pub fn pending_delegated(&self) -> u64 {
        self.0.pending_delegated
    }

    #[wasm_bindgen(getter, js_name = pendingDelegatedByActive)]
    pub fn pending_delegated_by_active(&self) -> u64 {
        self.0.pending_delegated_by_active
    }

    #[wasm_bindgen(getter, js_name = pendingRevoked)]
    pub fn pending_revoked(&self) -> u64 {
        self.0.pending_revoked
    }

    #[wasm_bindgen(getter, js_name = pendingRevokedByActive)]
    pub fn pending_revoked_by_active(&self) -> u64 {
        self.0.pending_revoked_by_active
    }
}
