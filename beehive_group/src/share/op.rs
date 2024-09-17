use crate::crypto::{share_key::ShareKey, signed::Signed};
use crate::principal::stateless::Stateless;
use std::collections::BTreeSet;

pub struct Add {
    pub id: Stateless,
    pub sharing_pubkey: ShareKey,
}

pub struct Retire {
    pub id: Stateless,
    pub sharing_pubkey: ShareKey,
}

pub struct Store {
    pub additions: BTreeSet<Signed<Add>>,
    pub retirements: BTreeSet<Signed<Retire>>,
}
