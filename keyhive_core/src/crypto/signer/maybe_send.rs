//! Conditional `Send` bound based on [`FutureForm`].
//!
//! This module provides a trait that conditionally requires `Send`
//! based on the future form being used.
//!
//! # Design
//!
//! For `Sendable`, we need the compiler to know that `T: MaybeSend<Sendable>` implies `T: Send`.
//! This is achieved by defining `MaybeSend` with an associated bound that varies by `K`.
//!
//! The approach uses separate impls for `Sendable` and `Local`:
//! - `impl<T: Send> MaybeSend<Sendable> for T` with `type Bound = T` where `T: Send`
//! - `impl<T> MaybeSend<Local> for T` with `type Bound = T` (no extra bounds)

use future_form::{FutureForm, Local, Sendable};

/// A marker trait for types that satisfy thread-safety requirements for the given [`FutureForm`].
///
/// - For `Sendable`: requires `Send`
/// - For `Local`: no requirements
///
/// # Associated Type
///
/// The `Proof` associated type witnesses that the bound is satisfied. For `Sendable`, this
/// is only implemented when `Self: Send`.
pub trait MaybeSend<K: FutureForm + ?Sized> {
    /// A witness that the required bounds are satisfied.
    /// For `Sendable`, this requires `Self: Send`.
    type Proof;
}

/// For `Sendable`, only `Send` types can implement `MaybeSend<Sendable>`.
impl<T: Send + ?Sized> MaybeSend<Sendable> for T {
    type Proof = ();
}

/// For `Local`, all types implement `MaybeSend<Local>`.
impl<T: ?Sized> MaybeSend<Local> for T {
    type Proof = ();
}

/// A marker trait that conditionally requires `Send + Sync` based on the [`FutureForm`].
///
/// - For `Sendable`: requires `Send + Sync`
/// - For `Local`: no requirements
pub trait MaybeSendSync<K: FutureForm + ?Sized> {
    type Proof;
}

impl<T: Send + Sync + ?Sized> MaybeSendSync<Sendable> for T {
    type Proof = ();
}

impl<T: ?Sized> MaybeSendSync<Local> for T {
    type Proof = ();
}
