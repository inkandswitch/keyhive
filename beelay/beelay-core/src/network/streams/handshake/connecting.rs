use crate::streams::connection::Connection;

use super::Handshake;

/// The state of a handshake
#[derive(Debug)]
pub(crate) enum Connecting {
    /// Still in progress
    Handshaking(Handshake),
    /// Finished successfully
    Complete(Box<Connection>),
    /// Failed for the given reason
    Failed(String),
}
