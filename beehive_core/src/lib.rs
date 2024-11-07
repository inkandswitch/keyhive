#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_debug_implementations,
    future_incompatible,
    let_underscore,
    missing_docs,
    rust_2021_compatibility,
    nonstandard_style
)]
#![deny(unreachable_pub)]

pub mod access;
pub mod content;
pub mod context;
pub mod crypto;
pub mod principal;
pub mod util;
