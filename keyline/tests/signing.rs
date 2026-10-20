//! Signing and verifying Keyline's payloads through `keyhive_crypto`'s
//! [`Signed`] and [`Verified`], and their wire frame.

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    digest::Digest,
    identifier::{Identifier, InvalidIdentifier},
    signable::{message, Kinded, Signable, TAG},
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

/// Bytes before the issuer in a frame: the `KH` tag, the kind and the version.
const HEADER_LEN: usize = TAG.len() + 2;

fn sample() -> Delegation {
    Delegation::new(id(2), id(3), Power::Edit)
}

fn signed_by<T: Signable>(value: &T, key: &SigningKey) -> Signed<T> {
    let (_, signed) = Verified::sign_sync(value, key)
        .expect("any valid key signs")
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

/// Signs what follows the tag, kind and version, as a signer written for
/// another protocol might. Answers through both signer traits, so the async
/// path that WebCrypto, HSM and KMS signers take is checked too.
struct Untagged(SigningKey);

impl Verifiable for Untagged {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

impl SyncSignerBasic for Untagged {
    fn try_sign_bytes_sync_basic(&self, bytes: &[u8]) -> Result<Signature, SigningError> {
        Ok(self.0.sign(&bytes[HEADER_LEN..]))
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for Untagged {
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

/// A signer whose verifying key is a small-order point, which cannot be an
/// issuer. It is never asked to sign.
struct Weak(VerifyingKey);

impl Verifiable for Weak {
    fn verifying_key(&self) -> VerifyingKey {
        self.0
    }
}

impl SyncSignerBasic for Weak {
    fn try_sign_bytes_sync_basic(&self, _: &[u8]) -> Result<Signature, SigningError> {
        panic!("a signer that cannot be an issuer is never asked to sign")
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for Weak {
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
    let expected = Verified::sign_sync(&sample(), &signing_key(1)).expect("any valid key signs");
    let local = ready(Verified::sign::<Local, _>(&sample(), &signer)).expect("any valid key signs");
    let sendable = ready(assert_send(Verified::sign::<Sendable, _>(
        &sample(),
        &signer,
    )))
    .expect("any valid key signs");
    assert_eq!(local, expected);
    assert_eq!(sendable, expected);
}

#[test]
fn signer_that_drops_the_tag_is_caught() {
    for result in sign_every_way(&sample(), &Untagged(signing_key(1))) {
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
fn a_signer_whose_key_cannot_be_an_issuer_is_refused() {
    use curve25519_dalek::constants::EIGHT_TORSION;
    let weak = VerifyingKey::from_bytes(&EIGHT_TORSION[1].compress().to_bytes())
        .expect("a small-order point decompresses");
    for result in sign_every_way(&sample(), &Weak(weak)) {
        assert!(matches!(
            result,
            Err(SignError::InvalidIssuer(InvalidIdentifier::SmallOrder))
        ));
    }
}

/// Whoever signs is the issuer, and the issuer is part of the identity: the
/// same payload signed by two keys is two statements.
#[test]
fn the_signer_is_the_issuer() {
    let alice = signed_by(&sample(), &signing_key(1));
    let bob = signed_by(&sample(), &signing_key(2));
    assert_eq!(alice.issuer(), id(1));
    assert_eq!(bob.issuer(), id(2));
    assert_ne!(alice.digest(), bob.digest());
}

#[test]
fn sign_then_verify() {
    let signed = signed_by(&sample(), &signing_key(1));
    let verified = signed.clone().verify().expect("verifies");
    assert_eq!(verified.payload(), &sample());
    assert_eq!(verified.issuer(), id(1));
    assert_eq!(verified.digest(), signed.digest());
    assert_eq!(**verified.signed(), signed);
}

#[test]
fn signature_and_digest_cover_the_same_bytes() {
    let signed = signed_by(&sample(), &signing_key(1));
    assert_eq!(signed.digest(), Digest::of(&id(1), &sample().encode()));
    assert!(id(1)
        .verifying_key()
        .verify_strict(
            &message::<Delegation>(&id(1), signed.encoded().as_bytes()),
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
    let signed = Signed::<Delegation>::new(id(1), encoded, bare);
    assert_eq!(signed.verify().unwrap_err(), VerifyError::BadSignature);
}

/// A signature that plain `verify` accepts and `verify_strict` rejects.
///
/// The issuer key is `[a]B + T` for a point `T` of order 8. It has mixed order,
/// so [`Identifier`] accepts it. With a small-order `R` and `S = k·a`, the
/// verification equation leaves `-[k]T`, which equals `R` for about one
/// candidate in eight. Plain `verify` accepts that; `verify_strict` rejects the
/// small-order `R`.
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
    let issuer =
        Identifier::from_bytes(point.compress().to_bytes()).expect("mixed order is accepted");

    let (encoded, message, signature) = (2..=u8::MAX)
        .flat_map(|n| EIGHT_TORSION.iter().map(move |r| (n, r)))
        .find_map(|(n, r)| {
            let encoded = Delegation::new(id(n), id(1), Power::Edit).encode();
            let message = message::<Delegation>(&issuer, encoded.as_bytes());
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
        Signed::<Delegation>::new(issuer, encoded, signature)
            .verify()
            .unwrap_err(),
        VerifyError::BadSignature
    );
}

/// `Signed` equality is the issuer, the received bytes and the signature, so
/// the same payload under a different signature is a different value.
/// `Verified` compares as the `Signed` it was built from.
#[test]
fn identity_is_issuer_bytes_and_signature() {
    let a = signed_by(&sample(), &signing_key(1));
    let forged = Signed::new(
        a.issuer(),
        a.encoded().clone(),
        Signature::from_bytes(&[0u8; 64]),
    );
    let read = Delegation::new(id(2), id(3), Power::Read);
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

/// The forgeries `verify` must catch: Alice's signature presented as Bob's,
/// and Bob's signature over a frame that names Alice.
#[test]
fn the_issuer_must_be_the_signer() {
    let alice = signed_by(&sample(), &signing_key(1));
    let renamed = Signed::<Delegation>::new(id(2), alice.encoded().clone(), *alice.signature());
    assert_eq!(renamed.verify().unwrap_err(), VerifyError::BadSignature);

    let encoded = sample().encode();
    let signature = signing_key(2).sign(&message::<Delegation>(&id(1), encoded.as_bytes()));
    let forged = Signed::<Delegation>::new(id(1), encoded, signature);
    assert_eq!(forged.verify().unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn tampered_bytes_fail() {
    // Edit → Read: still a canonical delegation, so only the signature
    // check can reject it.
    let signed = signed_by(&sample(), &signing_key(1));
    let mut bytes = signed.encoded().clone().into_bytes();
    bytes[Identifier::LEN * 2] = Power::Read as u8;
    assert!(Delegation::decode(&bytes).is_ok());
    let tampered = Signed::<Delegation>::new(
        id(1),
        Encoded::from_bytes_unchecked(bytes),
        *signed.signature(),
    );
    assert_eq!(tampered.verify().unwrap_err(), VerifyError::BadSignature);
}

#[test]
fn valid_signature_over_non_canonical_bytes_fails_to_decode() {
    // Sign bytes that carry a trailing zero: signature is fine, decode is not.
    let mut bytes = sample().encode().into_bytes();
    bytes.push(0);
    let signature = signing_key(1).sign(&message::<Delegation>(&id(1), &bytes));
    let signed = Signed::<Delegation>::new(id(1), Encoded::from_bytes_unchecked(bytes), signature);
    assert_eq!(
        signed.verify().unwrap_err(),
        VerifyError::Decode(DecodeError::TrailingBytes)
    );
}

#[test]
fn works_for_revocations() {
    let revoke = Digest::of(&id(1), &sample().encode());
    let revocation: Revocation<Vec<u8>> =
        Revocation::new(revoke).retaining([(id(3), vec![7])].into());
    let verified = Verified::sign_sync(&revocation, &signing_key(1)).expect("any valid key signs");
    assert_eq!(verified.payload(), &revocation);
    assert_eq!(verified.issuer(), id(1));
}

#[test]
fn sign_verify_round_trip_property() {
    bolero::check!()
        .with_arbitrary::<(Delegation, Revocation<Vec<u8>>, [u8; 32])>()
        .for_each(|(d, r, seed)| {
            let key = SigningKey::from(*seed);
            let verified = Verified::sign_sync(d, &key).expect("any valid key signs");
            assert_eq!(
                (verified.payload(), verified.issuer()),
                (d, Identifier::from(&key))
            );

            let verified = Verified::sign_sync(r, &key).expect("any valid key signs");
            assert_eq!(
                (verified.payload(), verified.issuer()),
                (r, Identifier::from(&key))
            );
        });
}

/// The frame is the tag, kind, version, issuer, payload length, payload and
/// signature, and decodes back to the same value.
#[test]
fn frame_round_trips() {
    let signed = signed_by(&sample(), &signing_key(1));
    let payload = signed.encoded().as_bytes();
    let bytes = signed.encode().into_bytes();
    assert_eq!(
        bytes[..HEADER_LEN],
        [b'K', b'H', Delegation::KIND.to_u8(), Delegation::VERSION]
    );
    assert_eq!(
        &bytes[HEADER_LEN..HEADER_LEN + Identifier::LEN],
        id(1).as_bytes()
    );
    let at = HEADER_LEN + Identifier::LEN;
    assert_eq!(
        usize::from(bytes[at]),
        payload.len(),
        "a one-byte bijou64 length"
    );
    assert_eq!(&bytes[at + 1..at + 1 + payload.len()], payload);
    assert_eq!(
        &bytes[at + 1 + payload.len()..],
        &signed.signature().to_bytes()
    );
    assert_eq!(Signed::<Delegation>::decode(&bytes), Ok(signed));
}

/// Frames are self-delimiting: a frame followed by other bytes reads back
/// with the rest untouched.
#[test]
fn a_frame_reads_off_the_front_of_longer_input() {
    let signed = signed_by(&sample(), &signing_key(1));
    let mut bytes = signed.encode().into_bytes();
    bytes.extend_from_slice(b"rest");
    assert_eq!(
        Signed::<Delegation>::decode_next(&bytes),
        Ok((signed, &b"rest"[..]))
    );
}

/// A frame that is not Keyhive's, or is for another kind or version, is
/// refused before its payload is read.
#[test]
fn frame_header_is_checked() {
    let good = signed_by(&sample(), &signing_key(1)).encode().into_bytes();

    let mut bytes = good.clone();
    bytes[0] = b'X';
    assert_eq!(
        Signed::<Delegation>::decode(&bytes),
        Err(DecodeError::NotKeyhive)
    );

    let mut bytes = good.clone();
    bytes[2] = Revocation::<()>::KIND.to_u8();
    assert_eq!(
        Signed::<Delegation>::decode(&bytes),
        Err(DecodeError::UnexpectedKind(bytes[2]))
    );

    let mut bytes = good;
    bytes[3] = Delegation::VERSION + 1;
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
    let signature = signing_key(1).sign(&message::<Revocation<()>>(&id(1), encoded.as_bytes()));
    let signed = Signed::<Delegation>::new(id(1), encoded, signature);
    assert_eq!(signed.verify().unwrap_err(), VerifyError::BadSignature);
}
