use super::{keyhive::InnerKeyhive, power::JsPower, principal::JsPrincipal};
use keyhive_core::principal::individual::id::IndividualId;
use keyhive_crypto::id::Id;
use keyline::power::Power;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Membership {
    pub(crate) who: JsPrincipal,
    pub(crate) can: Power,
}

impl Membership {
    /// The individuals among `members` whose prekeys this keyhive holds, with
    /// their power. A member whose prekeys have not arrived is left out.
    pub(crate) async fn individuals(
        keyhive: &InnerKeyhive,
        members: BTreeMap<Id, Power>,
    ) -> Vec<Membership> {
        let mut memberships = Vec::new();
        for (id, can) in members {
            if keyhive.has_individual(IndividualId(id)).await {
                let who = JsPrincipal::new(keyhive.get_principal(id)).await;
                memberships.push(Membership { who, can });
            }
        }
        memberships
    }
}

#[wasm_bindgen]
impl Membership {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsPrincipal {
        self.who.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsPower {
        JsPower(self.can)
    }
}
