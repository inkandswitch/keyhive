//! Signing and verifying Keyline's payloads through `keyhive_crypto`'s
//! [`Signed`] and [`Verified`], and their wire frame.

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{
    digest::Digest,
    id::Id,
    signable::{message, Kinded, Signable, PREFIX},
    signed::SigningError,
    signer::{async_signer::AsyncSigner, memory::MemorySigner, sync_signer::SyncSignerBasic},
    verifiable::Verifiable,
    verified::{SignError, Signed, Verified, VerifyError},
};
use keyline::{
    delegation::Delegation,
    power::Power,
    revocation::Revocation,
    test_utils::{id, signing_key},
};
use std::{
    future::Future,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

fn sample() -> Delegation {
    Delegation::new(id(1), id(2), id(3), Power::Edit)
}

fn signed_by<T: Signable + Verifiable>(value: &T, key: &SigningKey) -> Signed<T> {
    let (_, signed) = Verified::sign_sync(value, key)
        .expect("key is the issuer")
        .into_parts();
    Arc::unwrap_or_clone(signed)
}

/// Drive a future whose signer answers at once, as `MemorySigner` does.
fn ready<T, Fut: Future<Output = T>>(future: Fut) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("signer is synchronous"),
    }
}

/// Signs the payload without the prefix and header, as a signer written for
/// another protocol might. Answers through both signer traits, so the async
/// path that WebCrypto, HSM and KMS signers take is checked too.
struct Unprefixed(SigningKey);

impl Verifiable for Unprefixed {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl SyncSignerBasic for Unprefixed {
    fn try_sign_bytes_sync_basic(&self, bytes: &[u8]) -> Result<Signature, SigningError> {
        Ok(self.0.sign(&bytes[PREFIX.len() + 2..]))
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for Unprefixed {
    fn try_sign_bytes_async<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> F::Future<'a, Result<Signature, SigningError>> {
        F::ready(self.try_sign_bytes_sync_basic(bytes))
    }
}

/// A signer that fails, as a device that is locked or unplugged does.
struct Broken(SigningKey);

impl Verifiable for Broken {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl SyncSignerBasic for Broken {
    fn try_sign_bytes_sync_basic(&self, _: &[u8]) -> Result<Signature, SigningError> {
        Err(SignatureError::new().into())
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for Broken {
    fn try_sign_bytes_async<'a>(
        &'a self,
        bytes: &'a [u8],
    ) -> F::Future<'a, Result<Signature, SigningError>> {
        F::ready(self.try_sign_bytes_sync_basic(bytes))
    }
}

/// `value` signed by `signer` through each path: async `Local` and `Sendable`
/// (WebCrypto, an HSM, a KMS), and sync (an in-memory key).
fn sign_every_way<S>(value: &Delegation, signer: &S) -> [Result<Verified<Delegation>, SignError>; 3]
where
    S: AsyncSigner<Local> + AsyncSigner<Sendable> + SyncSignerBasic + Verifiable + Sync,
{
    [
        ready(Verified::sign::<Local, _>(value, signer)),
        ready(Verified::sign::<Sendable, _>(value, signer)),
        Verified::sign_sync(value, signer),
    ]
}

#[test]
fn async_signer_matches_sync() {
    fn assert_send<T: Send>(value: T) -> T {
        value
    }
    let signer = MemorySigner(signing_key(1));
    let expected = Verified::sign_sync(&sample(), &signing_key(1)).expect("key is the issuer");
    let local = ready(Verified::sign::<Local, _>(&sample(), &signer)).expect("key is the issuer");
    let sendable = ready(assert_send(Verified::sign::<Sendable, _>(
        &sample(),
        &signer,
    )))
    .expect("key is the issuer");
    assert_eq!(local, expected);
    assert_eq!(sendable, expected);
}

#[test]
fn signer_that_drops_the_header_is_caught() {
    for result in sign_every_way(&sample(), &Unprefixed(signing_key(1))) {
        assert!(matches!(
            result,
            Err(SignError::Unverifiable(VerifyError::BadSignature))
        ));
    }
}

#[test]
fn signer_failure_is_reported() {
    for result in sign_every_way(&sample(), &Broken(signing_key(1))) {
        assert!(matches!(result, Err(SignError::Signer(_))));
    }
}

#[test]
fn sign_then_verify() {
    let signed = signed_by(&sample(), &signing_key(1));
    let verified = signed.clone().verify().expect("verifies");
    assert_eq!(verified.payload(), &sample());
    assert_eq!(verified.payload().issuer, id(1));
    assert_eq!(verified.digest(), signed.digest());
    assert_eq!(**verified.signed(), signed);
}

#[test]
fn signature_and_digest_cover_the_same_bytes() {
    let signed = signed_by(&sample(), &signing_key(1));
    assert_eq!(signed.digest(), Digest::of(&sample().encode()));
    assert!(sample()
        .verifying_key()
        .verify_strict(
            &message::<Delegation>(signed.encoded().as_bytes()),
            signed.signature()
        )
        .is_ok());
}

/// A signature over the bare encoding, as another protocol sharing the
/// key might produce, is not a signature over the certificate.
#[test]
fn signature_without_the_header_fails() {
    let encoded = sample().encode();
    let bare = signing_key(1).sign(encoded.as_bytes());
    let signed = Signed::<Delegation>::from_parts(encoded, bare);
    assert_eq!(signed.verify().unwrap_err(), VerifyError::BadSignature);
}

/// A signature that plain `verify` accepts and `verify_strict` rejects.
///
/// The issuer key is `[a]B + T` for a point `T` of order 8. It has mixed
/// order, so [`Id`] accepts it. With a small-order `R` and `S = k·a`, the
/// verification equation leaves `-[k]T`, which equals `R` for about one
/// candidate in eight. Plain `verify` accepts that; `verify_strict`
/// rejects the small-order `R`.
#[test]
fn small_order_r_is_rejected() {
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
        scalar::Scalar,
    };
    use ed25519_dalek::Verifier;
    use sha2::{Digest as _, Sha512};

    let a = Scalar::from(0x5eed_u64);
    let torsion = EIGHT_TORSION[1];
    let point = a * ED25519_BASEPOINT_POINT + torsion;
    let issuer = Id::from_bytes(point.compress().to_bytes()).expect("mixed order is accepted");

    let (encoded, message, signature) = (2..=u8::MAX)
        .flat_map(|n| EIGHT_TORSION.iter().map(move |r| (n, r)))
        .find_map(|(n, r)| {
            let encoded = Delegation::new(issuer, id(n), id(1), Power::Edit).encode();
            let message = message::<Delegation>(encoded.as_bytes());
            let r_bytes = r.compress().to_bytes();
            let k = Scalar::from_bytes_mod_order_wide(
                &Sha512::new()
                    .chain_update(r_bytes)
                    .chain_update(issuer.as_bytes())
                    .chain_update(&message)
                    .finalize()
                    .into(),
            );
            (k * torsion == -r).then(|| {
                let signature = Signature::from_components(r_bytes, (k * a).to_bytes());
                (encoded, message, signature)
            })
        })
        .expect("about one candidate in eight works");

    assert!(issuer.verifying_key().verify(&message, &signature).is_ok());
    assert_eq!(
        Signed::<Delegation>::from_parts(encoded, signature)
            .verify()
            .unwrap_err(),
        VerifyError::BadSignature
    );
}

/// `Signed` equality is the received bytes plus the signature, so the same
/// payload under a different signature is a different value. `Verified`
/// compares as the `Signed` it was built from.
#[test]
fn identity_is_bytes_and_signature() {
    let a = signed_by(&sample(), &signing_key(1));
    let forged = Signed::from_parts(a.encoded().clone(), Signature::from_bytes(&[0u8; 64]));
    let read = Delegation::new(id(1), id(2), id(3), Power::Read);
    let other = signed_by(&read, &signing_key(1));
    assert_ne!(a, forged);
    assert_ne!(a, other);

    let verified = a.clone().verify().expect("verifies");
    assert_eq!(verified, a.clone().verify().expect("verifies"));
    assert_ne!(verified, other.verify().expect("verifies"));
    assert_eq!(Verifiable::verifying_key(&verified), id(1).verifying_key());
}

#[test]
fn hash_agrees_with_eq() {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };
    fn hash<T: Hash>(value: &T) -> u64 {
        let mut state = DefaultHasher::new();
        value.hash(&mut state);
        state.finish()
    }

    // `Hash` promises only that equal values hash equal.
    let a = signed_by(&sample(), &signing_key(1));
    let b = signed_by(&sample(), &signing_key(1));
    assert_eq!(hash(&a), hash(&b));

    let va = a.verify().expect("verifies");
    let vb = b.verify().expect("verifies");
    assert_eq!(hash(&va), hash(&vb));
}

#[test]
fn signing_with_a_key_that_is_not_the_issuer_is_refused() {
    assert!(matches!(
        Verified::sign_sync(&sample(), &signing_key(2)),
        Err(SignError::NotTheIssuer)
    ));
    assert!(matches!(
        ready(Verified::sign::<Local, _>(
            &sample(),
            &MemorySigner(signing_key(2))
        )),
        Err(SignError::NotTheIssuer)
    ));
}

/// The forgery `verify` must catch: a well-formed signature by Bob over a
/// payload that names Alice as issuer.
#[test]
fn signer_must_be_the_payload_issuer() {
    let forger = signing_key(2);
    let encoded = sample().encode(); // issuer = id(1)
    let signature = forger.sign(&message::<Delegation>(encoded.as_bytes()));
    let forged = Signed::<Delegation>::from_parts(encoded, signature);
    assert_eq!(forged.verify().unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn tampered_bytes_fail() {
    // Edit → Read: still a canonical delegation, so only the signature
    // check can reject it.
    let signed = signed_by(&sample(), &signing_key(1));
    let mut bytes = signed.encoded().clone().into_bytes();
    bytes[Id::LEN * 3] = Power::Read as u8;
    assert!(Delegation::decode(&bytes).is_ok());
    let tampered =
        Signed::<Delegation>::from_parts(Encoded::from_bytes_unchecked(bytes), *signed.signature());
    assert_eq!(tampered.verify().unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn valid_signature_over_non_canonical_bytes_fails_to_decode() {
    // Sign bytes that carry a trailing zero: signature is fine, decode is not.
    let key = signing_key(1);
    let mut bytes = sample().encode().into_bytes();
    bytes.push(0);
    let signature = key.sign(&message::<Delegation>(&bytes));
    let signed = Signed::<Delegation>::from_parts(Encoded::from_bytes_unchecked(bytes), signature);
    assert_eq!(
        signed.verify().unwrap_err(),
        VerifyError::Decode(DecodeError::TrailingBytes)
    );
}

#[test]
fn works_for_revocations() {
    let revocation: Revocation<Vec<u8>> =
        Revocation::new(id(1), sample().digest()).retaining([(id(3), vec![7])].into());
    let verified = Verified::sign_sync(&revocation, &signing_key(1)).expect("key is the issuer");
    assert_eq!(verified.payload(), &revocation);
}

#[test]
fn sign_verify_round_trip_property() {
    bolero::check!()
        .with_arbitrary::<(Delegation, Revocation<Vec<u8>>, [u8; 32])>()
        .for_each(|(d, r, seed)| {
            // Re-issue both under the generated key so they are signable.
            let key = SigningKey::from(*seed);
            let issuer = Id::from(&key);
            let d = Delegation { issuer, ..*d };
            let verified = Verified::sign_sync(&d, &key).expect("key is the issuer");
            assert_eq!(verified.payload(), &d);

            let r = Revocation {
                issuer,
                ..r.clone()
            };
            let verified = Verified::sign_sync(&r, &key).expect("key is the issuer");
            assert_eq!(verified.payload(), &r);
        });
}

/// The frame is version, kind, signature, payload, and decodes back to the
/// same value.
#[test]
fn frame_round_trips() {
    let signed = signed_by(&sample(), &signing_key(1));
    let bytes = signed.encode().into_bytes();
    assert_eq!(bytes[..2], [Delegation::VERSION, Delegation::KIND.to_u8()]);
    assert_eq!(&bytes[2..66], &signed.signature().to_bytes());
    assert_eq!(&bytes[66..], signed.encoded().as_bytes());
    assert_eq!(Signed::<Delegation>::decode(&bytes), Ok(signed));
}

/// A frame for another kind or version is refused before its payload is read.
#[test]
fn frame_header_is_checked() {
    let mut bytes = signed_by(&sample(), &signing_key(1)).encode().into_bytes();
    bytes[1] = Revocation::<()>::KIND.to_u8();
    assert_eq!(
        Signed::<Delegation>::decode(&bytes),
        Err(DecodeError::UnexpectedKind(bytes[1]))
    );
    bytes[1] = Delegation::KIND.to_u8();
    bytes[0] = Delegation::VERSION + 1;
    assert_eq!(
        Signed::<Delegation>::decode(&bytes),
        Err(DecodeError::UnsupportedVersion {
            kind: Delegation::KIND.to_u8(),
            version: Delegation::VERSION + 1
        })
    );
}

/// The signature covers the kind: one made for the same bytes as another kind
/// does not verify.
#[test]
fn signature_for_another_kind_fails() {
    let encoded = sample().encode();
    let signature = signing_key(1).sign(&message::<Revocation<()>>(encoded.as_bytes()));
    let signed = Signed::<Delegation>::from_parts(encoded, signature);
    assert_eq!(signed.verify().unwrap_err(), VerifyError::BadSignature);
}
