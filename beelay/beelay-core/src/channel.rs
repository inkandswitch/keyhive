//! Pairwise channels.
//!
//! The main types in this module are [`Manager`] and [`Session`].
//! The manager is responsible for managing your signing key, creating and managing many sessions.
//! Sessions track for sending and receiving messages, DH key exchange, and ratcheting.

pub mod ack;
pub mod connect;
pub mod counter_connect;
pub mod dial;
pub mod disconnect;
pub mod hash;
pub mod manager;
pub mod signed;
