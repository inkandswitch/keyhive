use std::collections::BTreeMap;

use crate::agent::Agentic;
use crate::capability::Capability;

// FIXME Identifiable? Pricipal?
pub trait Agent {
    fn public_key(&self) -> [u8; 32];

    fn get_caps(&self) -> BTreeMap<Agentic, Capability> {
        todo!()
    }
}
