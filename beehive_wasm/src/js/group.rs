use super::{
    capability::Capability, change_ref::JsChangeRef, group_id::JsGroupId, identifier::JsIdentifier,
};
use beehive_core::principal::group::Group;
use derive_more::{From, Into};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone, Dupe, From, Into)]
pub struct JsGroup(pub(crate) Rc<RefCell<Group<JsChangeRef>>>);

#[wasm_bindgen(js_class = Group)]
impl JsGroup {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.borrow().id())
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> JsGroupId {
        JsGroupId(self.0.borrow().group_id())
    }

    #[wasm_bindgen(getter)]
    pub fn members(&self) -> Vec<Capability> {
        self.0
            .borrow()
            .members()
            .iter()
            .map(|(_agent_id, dlgs)| {
                let best = dlgs
                    .iter()
                    .max_by_key(|dlg| dlg.payload().can())
                    .expect("should have at least one member");

                Capability {
                    who: dlgs.iter().next().unwrap().payload().delegate().clone(),
                    proof: best.clone(),
                }
            })
            .collect()
    }
}
