#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_debug_implementations,
    future_incompatible,
    let_underscore,
//     missing_docs,
    rust_2021_compatibility,
    nonstandard_style
)]
#![deny(unreachable_pub)]

pub mod ability;
pub mod access;
pub mod archive;
pub mod cgka;
pub mod contact_card;
pub mod content;
pub mod crypto;
#[cfg(feature = "debug_events")]
pub mod debug_events;
pub mod error;
pub mod event;
pub mod invocation;
pub mod keyhive;
pub mod listener;
pub mod principal;
pub mod store;
pub mod util;
