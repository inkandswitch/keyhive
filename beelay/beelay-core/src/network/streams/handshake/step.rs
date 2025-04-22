use crate::streams::OutboundMessage;

use super::Connecting;

#[derive(Debug)]
pub(crate) struct Step {
    /// The current state of the handshake
    pub(crate) state: Connecting,
    /// The next message to send, if there is one
    pub(crate) next_msg: Option<OutboundMessage>,
}
