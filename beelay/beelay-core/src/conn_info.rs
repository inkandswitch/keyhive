use crate::{streams::SyncPhase, PeerId, UnixTimestampMillis};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub peer_id: PeerId,
    pub state: ConnState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnState {
    Syncing {
        started_at: UnixTimestampMillis,
    },
    Listening {
        last_synced_at: Option<UnixTimestampMillis>,
    },
}

impl From<SyncPhase> for ConnState {
    fn from(phase: SyncPhase) -> Self {
        match phase {
            SyncPhase::Syncing { started_at } => ConnState::Syncing { started_at },
            SyncPhase::Listening { last_synced_at } => ConnState::Listening { last_synced_at },
        }
    }
}
