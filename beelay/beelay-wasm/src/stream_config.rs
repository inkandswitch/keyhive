use beelay_core::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "direction")]
pub enum StreamConfig {
    #[serde(rename = "accepting")]
    Accepting {
        #[serde(rename = "receiveAudience")]
        receive_audience: Option<String>,
    },
    #[serde(rename = "connecting")]
    Connecting {
        #[serde(rename = "remoteAudience")]
        remote_audience: Audience,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Audience {
    #[serde(rename = "peerId")]
    PeerId {
        #[serde(rename = "peerId", with = "crate::js_wrappers::peer_id")]
        peer_id: PeerId,
    },
    #[serde(rename = "serviceName")]
    ServiceName {
        #[serde(rename = "serviceName")]
        service_name: String,
    },
}

impl From<Audience> for beelay_core::Audience {
    fn from(value: Audience) -> Self {
        match value {
            Audience::PeerId { peer_id } => beelay_core::Audience::peer(&peer_id),
            Audience::ServiceName { service_name } => {
                beelay_core::Audience::service_name(service_name)
            }
        }
    }
}

impl From<StreamConfig> for beelay_core::StreamDirection {
    fn from(value: StreamConfig) -> Self {
        match value {
            StreamConfig::Accepting { receive_audience } => {
                beelay_core::StreamDirection::Accepting { receive_audience }
            }
            StreamConfig::Connecting { remote_audience } => {
                beelay_core::StreamDirection::Connecting {
                    remote_audience: remote_audience.into(),
                }
            }
        }
    }
}
