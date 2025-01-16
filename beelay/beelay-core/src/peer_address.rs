use crate::{auth::audience::Audience, effects, endpoint, stream};

pub use error::BadTransport;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PeerAddress {
    Endpoint(endpoint::EndpointId),
    Stream(stream::StreamId),
}

impl From<endpoint::EndpointId> for PeerAddress {
    fn from(value: endpoint::EndpointId) -> Self {
        Self::Endpoint(value)
    }
}

impl From<stream::StreamId> for PeerAddress {
    fn from(value: stream::StreamId) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct TargetNodeInfo {
    target: PeerAddress,
    audience: Audience,
    pub(crate) last_known_peer_id: Option<crate::PeerId>,
}

impl std::fmt::Display for TargetNodeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TargetNodeInfo(target: {:?}, audience: {:?}, last_known_peer_id: {:?})",
            self.target, self.audience, self.last_known_peer_id
        )
    }
}

impl TargetNodeInfo {
    pub(crate) fn lookup<R: rand::Rng + rand::CryptoRng>(
        effects: &effects::TaskEffects<R>,
        target: PeerAddress,
        last_known_peer_id: Option<crate::PeerId>,
    ) -> Result<Self, BadTransport> {
        let audience = match target {
            PeerAddress::Endpoint(endpoint_id) => effects
                .endpoint_audience(endpoint_id)
                .ok_or_else(|| BadTransport::MissingEndpoint(endpoint_id))?,
            PeerAddress::Stream(stream_id) => effects
                .stream_audience(stream_id)
                .ok_or_else(|| BadTransport::MissingStream(stream_id))?,
        };
        Ok(Self {
            target,
            audience,
            last_known_peer_id,
        })
    }

    pub(crate) fn new(
        target: PeerAddress,
        audience: Audience,
        last_known_peer_id: Option<crate::PeerId>,
    ) -> Self {
        Self {
            target,
            audience,
            last_known_peer_id,
        }
    }

    pub(crate) fn audience(&self) -> Audience {
        self.audience
    }

    pub fn target(&self) -> &PeerAddress {
        &self.target
    }

    pub fn is_source_of(&self, remote: &crate::PeerId) -> bool {
        self.last_known_peer_id == Some(*remote) || self.audience == Audience::peer(remote)
    }
}

mod error {
    use crate::{endpoint, stream};

    #[derive(Debug)]
    pub enum BadTransport {
        MissingEndpoint(endpoint::EndpointId),
        MissingStream(stream::StreamId),
    }

    impl std::fmt::Display for BadTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::MissingEndpoint(endpoint_id) => {
                    write!(f, "missing endpoint: {:?}", endpoint_id)
                }
                Self::MissingStream(stream_id) => {
                    write!(f, "missing stream: {:?}", stream_id)
                }
            }
        }
    }

    impl std::error::Error for BadTransport {}
}
