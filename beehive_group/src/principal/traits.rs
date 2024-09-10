use super::agent::Agent;
// use crate::capability::Capability;
// use std::collections::{BTreeMap, BTreeSet};

// FIXME Identifiable? Pricipal?
// pub trait Agent {
//     fn public_key(&self) -> [u8; 32];
//
//     fn get_caps(&self) -> BTreeMap<Agentic, Capability> {
//         todo!()
//     }
// }

pub trait Identifiable {
    fn id(&self) -> [u8; 32];
    // FIXME fn capabilities(&self) -> BTreeMap<Agent, BTreeSet<Capability>>; // FIXME set vs vec here?
}

pub trait Group {
    fn members(&self) -> Vec<Agent>;
    fn transitive_members(&self) -> Vec<Agent>;
}
