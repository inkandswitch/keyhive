use std::collections::BTreeMap;

use crate::capability::Capability;
use crate::principal::agent::Agent;

// FIXME move to capabilty store
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    pub store: BTreeMap<Agent, Capability>,
}
