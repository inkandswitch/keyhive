//! Pairwise channels.
//!
//! The main types in this module are [`Manager`] and [`Session`].
//! The manager is responsible for managing your signing key, creating and managing many sessions.
//! Sessions track for sending and receiving messages, DH key exchange, and ratcheting.

pub mod dial;
pub mod encrypted;
pub mod hang_up;
pub mod manager;
pub mod message;
pub mod session;
pub mod signed;
