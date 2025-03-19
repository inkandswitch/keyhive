//! Event listeners.
//!
//! Listeners are hooks for reacting to when important events happen in Keyhive.
//! This can be helpful for logging, live streaming of changes, gossip, and so on.
//!
//! If you don't want this feature, use the default listener: [`NoListener`].
//! [`NoListener`] is set as the default listener, so in most common cases manually
//! setting [`NoListener`] is not necessary.
//!
//! [`NoListener`]: self::no_listener::NoListener

pub mod cgka;
pub mod deque;
pub mod log;
pub mod membership;
pub mod no_listener;
pub mod prekey;
