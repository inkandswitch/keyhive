use crate::access::Access;
use crate::agent::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability {
    // delegate: &Agent,
    subject: Stateless, // FIXME rename to ID
    can: Access,
}
