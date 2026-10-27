//! A prekey operation counts only once its signature checks out against its
//! issuer, the first one for an identifier included, whichever way it
//! arrives: as an event, in a contact card, or in an archive.

use ed25519_dalek::Signature;
use keyhive_codec::{
    encoded::Encoded,
    prefixed::encode_list,
    traits::{Decode, Encode},
};
use keyhive_core::{
    contact_card::ContactCard,
    event::static_event::StaticEvent,
    keyhive::ReceiveStaticEventError,
    principal::individual::{
        id::IndividualId,
        op::{add_key::AddKeyOp, KeyOp, SignedKeyOp},
        state::PrekeyState,
        IndividualState, ReceivePrekeyOpError,
    },
    test_utils::make_simple_keyhive,
};
use keyhive_crypto::{
    identifier::Identifier,
    share_key::ShareSecretKey,
    signable::message,
    signer::{memory::MemorySigner, sync_signer::SyncSignerBasic},
    verifiable::Verifiable,
    verified::{Signed, Verified, VerifyError},
};
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use testresult::TestResult;

/// An add claiming to be `victim`'s, carrying a fresh key and a garbage
/// signature: nobody holding `victim`'s signing key took part.
fn forged_add(victim: Identifier) -> Signed<AddKeyOp> {
    let op = AddKeyOp {
        share_key: ShareSecretKey::generate(&mut OsRng).share_key(),
    };
    Signed::new(victim, op.encode(), Signature::from_bytes(&[0; 64]))
}

fn add(signer: &MemorySigner) -> KeyOp {
    let op = AddKeyOp {
        share_key: ShareSecretKey::generate(&mut OsRng).share_key(),
    };
    KeyOp::Add(Verified::sign_sync(&op, signer).expect("signing succeeds"))
}

#[tokio::test]
async fn a_forged_first_prekey_op_is_refused() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let carol = make_simple_keyhive().await?;

    let result = alice
        .receive_static_event(StaticEvent::PrekeysExpanded(forged_add(carol.id().into())))
        .await;

    assert!(
        matches!(&result, Err(e) if e.is_final()),
        "refused for good, not kept pending: {result:?}"
    );
    assert!(!alice.has_individual(carol.id()).await, "carol is unknown");
    Ok(())
}

#[tokio::test]
async fn a_forged_prekey_op_cannot_turn_a_group_into_an_individual() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let group = alice.generate_group(vec![]).await?;

    let result = alice
        .receive_static_event(StaticEvent::PrekeysExpanded(forged_add(group.into())))
        .await;

    assert!(result.is_err());
    assert!(alice.has_group(group).await?, "still a group");
    assert!(!alice.has_individual(IndividualId(group.into())).await);
    Ok(())
}

#[tokio::test]
async fn a_prekey_op_carrying_a_small_order_key_is_refused() -> TestResult {
    let alice = make_simple_keyhive().await?;
    let signer = MemorySigner::generate(&mut OsRng);
    let issuer = Identifier::try_from(signer.verifying_key())?;
    // The u-coordinate 0 is a point of small order: a key agreement with it
    // gives a secret anyone can compute. The issuer genuinely signs it.
    let payload = vec![0; 32];
    let signature = signer.try_sign_bytes_sync_basic(&message::<AddKeyOp>(&issuer, &payload))?;
    let signed = Signed::new(issuer, Encoded::from_bytes_unchecked(payload), signature);

    let result = alice
        .receive_static_event(StaticEvent::PrekeysExpanded(signed))
        .await;

    assert!(
        matches!(
            result,
            Err(ReceiveStaticEventError::ReceivePrekeyOpError(
                ReceivePrekeyOpError::Verify(VerifyError::Decode(_))
            ))
        ),
        "{result:?}"
    );
    assert!(!alice.has_individual(IndividualId(issuer)).await);
    Ok(())
}

#[tokio::test]
async fn a_contact_card_decodes_only_if_its_signature_verifies() -> TestResult {
    let carol = make_simple_keyhive().await?;
    let card = carol.generate_contact_card().await?;
    let bytes = card.to_bytes();
    assert_eq!(ContactCard::from_bytes(&bytes)?, card);

    // The signature is the last field.
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(ContactCard::from_bytes(&tampered).is_err());
    Ok(())
}

/// An archived individual is its prekey operations' frames, in digest order;
/// every one must be signed by the same key, which becomes its id.
#[test]
fn an_individual_decodes_only_from_one_issuers_operations() -> TestResult {
    let frames = |state: &PrekeyState| {
        let ops: BTreeMap<_, _> = state
            .ops()
            .values()
            .map(|op| (op.digest(), SignedKeyOp::from(op.as_ref().clone())))
            .collect();
        let mut bytes = Vec::new();
        encode_list(ops.values(), &mut bytes);
        bytes
    };
    let alice = MemorySigner::generate(&mut OsRng);
    let mallory = MemorySigner::generate(&mut OsRng);

    let mut state = PrekeyState::new(add(&alice));
    state.insert_op(add(&alice));
    let individual = IndividualState::decode(&frames(&state))?;
    assert_eq!(
        Identifier::from(individual.id()),
        Identifier::try_from(alice.verifying_key())?
    );
    assert_eq!(individual.prekeys().len(), 2);
    assert_eq!(individual.encode().into_bytes(), frames(&state));

    state.insert_op(add(&mallory));
    assert!(IndividualState::decode(&frames(&state)).is_err());
    Ok(())
}
