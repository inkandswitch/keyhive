use super::{
    archive::JsSerializationError, change_id::JsChangeId, identifier::JsIdentifier,
    keyhive::InnerKeyhive,
};
use keyhive_codec::traits::Encode;
use keyhive_core::{
    event::{static_event::StaticEvent, Event},
    principal::Principal,
};
use wasm_bindgen::prelude::*;

/// Any identifier, as this keyhive knows it.
///
/// `isIndividual`, `isGroup` and `isDocument` report what the keyhive knew
/// when this was made. It only ever learns more, so they can lag behind; ask
/// for a fresh `Principal` to see newer evidence.
#[wasm_bindgen(js_name = Principal)]
#[derive(Debug, Clone)]
pub struct JsPrincipal {
    pub(crate) inner: Principal<InnerKeyhive>,
    is_individual: bool,
    is_document: bool,
    is_group: bool,
}

impl JsPrincipal {
    /// A principal, with what the keyhive knows of it now.
    pub(crate) async fn new(inner: Principal<InnerKeyhive>) -> Self {
        let is_individual = inner.as_individual().await.is_some();
        let is_document = inner.as_document().await.is_some();
        let is_group = inner.as_group().await.is_ok_and(|g| g.is_some());
        JsPrincipal {
            inner,
            is_individual,
            is_document,
            is_group,
        }
    }
}

#[wasm_bindgen(js_class = Principal)]
impl JsPrincipal {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.inner.id())
    }

    /// The whole identifier, as `Identifier.toString()` gives it: `0x` and 64
    /// hex digits.
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        format!("{:#x}", self.inner.id())
    }

    #[wasm_bindgen(getter, js_name = isActive)]
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    #[wasm_bindgen(getter, js_name = isIndividual)]
    pub fn is_individual(&self) -> bool {
        self.is_individual
    }

    #[wasm_bindgen(getter, js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        self.is_group
    }

    #[wasm_bindgen(getter, js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        self.is_document
    }

    /// The prekey operations this keyhive holds for this principal, as a
    /// `Map` of hash to serialized `StaticEvent` bytes. Empty unless it is an
    /// individual.
    #[wasm_bindgen(js_name = keyOps)]
    #[allow(clippy::mutable_key_type)]
    pub async fn key_ops(&self) -> Result<js_sys::Map, JsSerializationError> {
        let map = js_sys::Map::new();
        if let Some(individual) = self.inner.as_individual().await {
            for key_op in individual.prekey_ops().await.values() {
                let event: Event<JsChangeId> = Event::from(key_op.as_ref().clone());
                let hash = js_sys::Uint8Array::from(event.digest().as_slice());
                let bytes = StaticEvent::from(event).encode().into_bytes();
                map.set(
                    &hash.into(),
                    &js_sys::Uint8Array::from(bytes.as_slice()).into(),
                );
            }
        }
        Ok(map)
    }

    /// The hashes of [`Self::key_ops`].
    #[wasm_bindgen(js_name = keyOpHashes)]
    pub async fn key_op_hashes(&self) -> Vec<js_sys::Uint8Array> {
        let Some(individual) = self.inner.as_individual().await else {
            return Vec::new();
        };
        individual
            .prekey_ops()
            .await
            .values()
            .map(|key_op| {
                let event: Event<JsChangeId> = Event::from(key_op.as_ref().clone());
                event.digest().as_slice().into()
            })
            .collect()
    }
}
