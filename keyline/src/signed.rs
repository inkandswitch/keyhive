//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.

/// Placeholder; see `design/keyline/implementation.md#signedt-and-verifiedt`.
pub struct Signed<T>(core::marker::PhantomData<T>);

/// Placeholder; the only constructor will be `Signed::verify`.
pub struct Verified<T>(core::marker::PhantomData<T>);
