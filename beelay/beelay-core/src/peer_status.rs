use crate::UnixTimestampMillis;

#[derive(Debug)]
pub struct PeerStatus {
    pub last_sent: Option<UnixTimestampMillis>,
    pub last_received: Option<UnixTimestampMillis>,
    pub state: PeerState,
}

#[derive(Debug)]
pub enum PeerState {
    Connecting,
    Syncing,
    Listening,
}
