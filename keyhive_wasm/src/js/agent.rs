use super::{
    archive::JsSerializationError, change_id::JsChangeId, event_handler::JsEventHandler,
    identifier::JsIdentifier, signer::JsSigner,
};
use derive_more::{Deref, Display, From, Into};
use dupe::Dupe;
use keyhive_core::{
    crypto::digest::Digest,
    event::{static_event::StaticEvent, Event},
    principal::agent::Agent,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Agent)]
#[derive(Debug, Clone, From, Into, Deref, Display)]
pub struct JsAgent(pub(crate) Agent<JsSigner, JsChangeId, JsEventHandler>);

#[wasm_bindgen(js_class = Agent)]
impl JsAgent {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0
            .id()
            .as_slice()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                acc.push_str(&format!("{:#x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = isIndividual)]
    pub fn is_individual(&self) -> bool {
        matches!(self.0, Agent::Individual(_, _))
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        matches!(self.0, Agent::Group(_, _))
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        matches!(self.0, Agent::Document(_, _))
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.id())
    }

    /// Returns prekey operations for this agent as a Map of hash -> serialized bytes for [`StaticEvent`]
    #[wasm_bindgen(js_name = keyOps)]
    #[allow(clippy::mutable_key_type)]
    pub async fn key_ops(&self) -> Result<js_sys::Map, JsSerializationError> {
        let key_ops = self.0.key_ops().await;
        let map = js_sys::Map::new();
        for key_op in key_ops {
            let event: Event<JsSigner, JsChangeId, JsEventHandler> =
                Event::from(key_op.as_ref().dupe());
            let digest = Digest::hash(&event);
            let hash = js_sys::Uint8Array::from(digest.as_slice());
            let static_event = StaticEvent::from(event);
            let bytes = bincode::serialize(&static_event).map_err(JsSerializationError::from)?;
            let js_bytes = js_sys::Uint8Array::from(bytes.as_slice());
            map.set(&hash.into(), &js_bytes.into());
        }
        Ok(map)
    }
}
