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
//! Both are slow and obviously correct. A backend must agree with both on
//! every generated set, and their agreement with each other checks that the
//! two forms in the design document say the same thing.

pub mod naive;
pub mod threshold;

use crate::{id::Id, power::Power};
use alloc::collections::BTreeMap;

/// `(subject, node) -> level`.
pub type Levels = BTreeMap<(Id, Id), Power>;
