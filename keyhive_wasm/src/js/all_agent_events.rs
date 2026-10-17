use wasm_bindgen::prelude::*;

/// Result of [`JsKeyhive::all_agent_events`](crate::js::keyhive::JsKeyhive::all_agent_events),
/// containing all events for all principals with deduplicated storage and
/// two-tier indirection for membership, prekey, and CGKA ops.
///
/// The consumer follows: agent -> source IDs -> hashes -> event bytes.
#[wasm_bindgen(js_name = AllAgentEvents)]
pub struct JsAllAgentEvents {
    /// All events deduplicated: `Map<Uint8Array(hash), Uint8Array(eventBytes)>`
    pub(crate) events: js_sys::Map,
    /// Keyline certificates per group or document (its closure):
    /// `Map<Uint8Array(subjectId), Uint8Array[](hashes)>`
    pub(crate) membership_sources: js_sys::Map,
    /// Principal -> the certificates that explain its removal from subjects it
    /// stood over: `Map<Uint8Array(principalId), Uint8Array[](hashes)>`
    pub(crate) explanations: js_sys::Map,
    /// Principal -> the subjects it stands over:
    /// `Map<Uint8Array(principalId), Uint8Array[](subjectIdBytes)>`
    pub(crate) agent_membership_sources: js_sys::Map,
    /// Prekey ops per source: `Map<Uint8Array(identifierBytes), Uint8Array[](hashes)>`
    pub(crate) prekey_sources: js_sys::Map,
    /// Principal -> prekey sources: `Map<Uint8Array(principalId), Uint8Array[](identifierBytes)>`
    pub(crate) agent_prekey_sources: js_sys::Map,
    /// CGKA ops per doc: `Map<Uint8Array(docId), Uint8Array[](hashes)>`
    pub(crate) cgka_sources: js_sys::Map,
    /// Principal -> CGKA sources: `Map<Uint8Array(principalId), Uint8Array[](docIdBytes)>`
    pub(crate) agent_cgka_sources: js_sys::Map,
}

#[wasm_bindgen(js_class = AllAgentEvents)]
impl JsAllAgentEvents {
    #[wasm_bindgen(getter)]
    pub fn events(&self) -> js_sys::Map {
        self.events.clone()
    }

    #[wasm_bindgen(getter, js_name = membershipSources)]
    pub fn membership_sources(&self) -> js_sys::Map {
        self.membership_sources.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn explanations(&self) -> js_sys::Map {
        self.explanations.clone()
    }

    #[wasm_bindgen(getter, js_name = agentMembershipSources)]
    pub fn agent_membership_sources(&self) -> js_sys::Map {
        self.agent_membership_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = prekeySources)]
    pub fn prekey_sources(&self) -> js_sys::Map {
        self.prekey_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = agentPrekeySources)]
    pub fn agent_prekey_sources(&self) -> js_sys::Map {
        self.agent_prekey_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = cgkaSources)]
    pub fn cgka_sources(&self) -> js_sys::Map {
        self.cgka_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = agentCgkaSources)]
    pub fn agent_cgka_sources(&self) -> js_sys::Map {
        self.agent_cgka_sources.clone()
    }
}
