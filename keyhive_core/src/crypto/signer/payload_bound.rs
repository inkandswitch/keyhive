//! Payload bounds abstraction for `FutureForm` variants.
//!
//! This module provides the [`PayloadBound`] trait which allows requiring
//! different bounds on payload types depending on whether we're using
//! [`Sendable`] or [`Local`] futures.
//!
//! [`Sendable`]: future_form::Sendable
//! [`Local`]: future_form::Local

use future_form::{FutureForm, Local, Sendable};

/// Marker trait for payload bounds that vary by [`FutureForm`].
///
/// When using [`Sendable`], payloads must be `Send`.
/// When using [`Local`], no additional bounds are required.
///
/// # Example
///
/// ```rust,ignore
/// use future_form::FutureForm;
/// use keyhive_core::crypto::signer::payload_bound::PayloadBound;
///
/// trait AsyncSigner<K: FutureForm> {
///     fn sign<'a, T>(&'a self, payload: &'a T) -> K::Future<'a, Signature>
///     where
///         T: Serialize + PayloadBound<K>;
/// }
/// ```
pub trait PayloadBound<K: FutureForm> {}

impl<T: Send> PayloadBound<Sendable> for T {}

impl<T> PayloadBound<Local> for T {}
