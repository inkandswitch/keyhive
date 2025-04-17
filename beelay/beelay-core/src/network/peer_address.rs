use crate::{network::endpoint, streams};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerAddress {
    Endpoint(endpoint::EndpointId),
    Stream(streams::StreamId),
}

impl From<endpoint::EndpointId> for PeerAddress {
    fn from(value: endpoint::EndpointId) -> Self {
        Self::Endpoint(value)
    }
}

impl From<streams::StreamId> for PeerAddress {
    fn from(value: streams::StreamId) -> Self {
        Self::Stream(value)
    }
}

impl std::fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(stream) => write!(f, "stream({:?}", stream),
            Self::Endpoint(endpoint) => write!(f, "endpoint({:?})", endpoint),
        }
    }
}
