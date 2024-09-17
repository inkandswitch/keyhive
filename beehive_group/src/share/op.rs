use crate::crypto::share_key::ShareKey;
use crate::principal::stateless::Stateless;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Add {
    pub id: Stateless,
    pub sharing_pubkey: ShareKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Replace {
    pub id: Stateless,
    pub prev: ShareKey,
    pub next: ShareKey,
}
