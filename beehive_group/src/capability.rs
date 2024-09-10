use crate::access::Access;
use crate::principal::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    // delegate: &Agent,
    subject: Stateless, // FIXME rename to ID, but needs to be stateful or doc
    can: Access,
}
