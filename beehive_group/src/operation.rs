use crate::agent::stateful::Stateful;
use crate::agent::stateless::Stateless;
use crate::capability::Capability;

pub enum Operation {
    Delegate {
        from: Stateless,
        to: Stateful,

        group: Stateless,
        what: Capability,
    },

    RevokeAgent {
        // FIXME should be the specific cap, not user?
        who: Stateless,
    },
}
