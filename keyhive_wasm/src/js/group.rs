use super::{
    capability::Capability, group_id::JsGroupId, identifier::JsIdentifier, keyhive::InnerKeyhive,
    keyline_storage_error::JsKeylineStorageError, membership::Membership,
    membership_list::direct_members, principal::JsPrincipal,
};
use keyhive_core::principal::group::Group;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone)]
pub struct JsGroup(pub(crate) Group<InnerKeyhive>);

#[wasm_bindgen(js_class = Group)]
impl JsGroup {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.id())
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> JsGroupId {
        JsGroupId(self.0.group_id())
    }

    /// Every individual who reaches this group, following nested groups all
    /// the way down, with the power for each one.
    #[wasm_bindgen(js_name = transitiveMembers)]
    pub async fn transitive_members(&self) -> Result<Vec<Membership>, JsKeylineStorageError> {
        let members = self.0.transitive_members().await?;
        Ok(Membership::individuals(self.0.keyhive(), members).await)
    }

    /// The direct members: each live delegation about this group, at the best
    /// power it gives per member.
    #[wasm_bindgen]
    pub async fn members(&self) -> Result<Vec<Capability>, JsKeylineStorageError> {
        direct_members(self.0.keyhive(), self.0.group_id().into()).await
    }

    #[wasm_bindgen(js_name = toPrincipal)]
    pub async fn to_principal(&self) -> JsPrincipal {
        JsPrincipal::new(self.0.keyhive().get_principal(self.0.id())).await
    }
}
