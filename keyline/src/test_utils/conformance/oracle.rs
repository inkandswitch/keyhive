//! Two oracles for the conformance laws, sharing no code with each other or
//! with any backend:
//!
//! - [`naive`] transcribes the value-form program in
//!   `design/keyline/implementation.md` § Evaluation, with caps as a second
//!   fixed point.
//! - [`threshold`] transcribes the threshold form in the same document rule
//!   for rule: levels as thresholds, one context per covered certificate, and
//!   no cap fixed point at all.
//!
//! Both follow the design document line by line and make no attempt at speed. A backend must agree with both on every generated set, and a law
//! with no backend checks that they agree with each other.
//!
//! Both share their inputs with every backend: `Delegation::digest`, `Power`'s
//! order, and the generator. A bug there would pass every law; the unit tests
//! in those modules are what catch it.

pub mod naive;
pub mod threshold;

use crate::{id::Id, power::Power};
use alloc::collections::BTreeMap;

/// `(subject, node) -> level`.
pub type Levels = BTreeMap<(Id, Id), Power>;
