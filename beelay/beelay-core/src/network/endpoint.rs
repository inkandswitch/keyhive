use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{network::TargetNodeInfo, Audience, Forwarding, PeerAddress};

pub(crate) struct Endpoints {
    endpoints: HashMap<EndpointId, Endpoint>,
}

impl Endpoints {
    pub(crate) fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
        }
    }

    pub(crate) fn register_endpoint(
        &mut self,
        audience: Audience,
        forwarding: Forwarding,
    ) -> EndpointId {
        let id = EndpointId::new();
        self.endpoints.insert(
            id,
            Endpoint {
                id,
                audience,
                forwarding,
            },
        );
        id
    }

    pub(crate) fn unregister_endpoint(&mut self, endpoint_id: EndpointId) {
        self.endpoints.remove(&endpoint_id);
    }

    pub(crate) fn audience_of(&self, endpoint_id: EndpointId) -> Option<Audience> {
        self.endpoints.get(&endpoint_id).map(|e| e.audience)
    }

    pub(crate) fn forward_targets(&self) -> impl Iterator<Item = TargetNodeInfo> + '_ {
        self.endpoints.values().filter_map(|e| {
            if e.forwarding == Forwarding::Forward {
                Some(TargetNodeInfo::new(
                    PeerAddress::Endpoint(e.id),
                    e.audience,
                    None,
                ))
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointId(u64);

static LAST_ENDPOINT_ID: AtomicU64 = AtomicU64::new(0);

impl EndpointId {
    fn new() -> Self {
        Self(LAST_ENDPOINT_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn serialize(&self) -> u64 {
        self.0
    }

    pub fn from_serialized(serialized: u64) -> Self {
        Self(serialized)
    }
}

pub struct Endpoint {
    id: EndpointId,
    audience: Audience,
    forwarding: Forwarding,
}
