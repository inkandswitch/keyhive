use std::collections::BTreeSet;

use super::{group::operation::Operation, identifier::Identifier};
use crate::{
    crypto::{hash::Hash, signed::Signed},
    util::content_addressed_map::CaMap,
};

pub trait AuthState {
    fn id(&self) -> Identifier;
    fn auth_heads(&self) -> &BTreeSet<Hash<Signed<Operation>>>;
    fn auth_heads_mut(&mut self) -> &mut BTreeSet<Hash<Signed<Operation>>>;
    fn auth_ops(&self) -> &CaMap<Signed<Operation>>;
    fn auth_ops_mut(&mut self) -> &mut CaMap<Signed<Operation>>;
}
