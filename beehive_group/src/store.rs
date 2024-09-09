use std::collections::BTreeMap;

use crate::agent::Agentic;
use crate::capability::Capability;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    pub store: BTreeMap<Agentic, Capability>,
}
