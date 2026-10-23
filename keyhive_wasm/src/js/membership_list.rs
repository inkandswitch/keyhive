//! The direct members of a group or document, read from Keyline.

use super::{
    capability::Capability, keyhive::InnerKeyhive, keyline_storage_error::JsKeylineStorageError,
    signed_delegation::JsSignedDelegation,
};
use keyhive_core::{certificate::decode_stored, principal::membered::id::MemberedId};
use keyhive_crypto::identifier::Identifier;
use keyline::delegation::Delegation;
use std::collections::BTreeMap;

/// Each direct member of `subject`, at the best power a live delegation
/// gives it, with that delegation. A delegation gives its audience what it
/// names, but no more than its issuer holds over the subject: Keyline clamps
/// each edge to its issuer's standing. A root edge is issued by the subject
/// itself.
pub(crate) async fn direct_members(
    keyhive: &InnerKeyhive,
    subject: MemberedId,
) -> Result<Vec<Capability>, JsKeylineStorageError> {
    let held = keyhive.reachable_members(subject).await?;
    let subject_id = Identifier::from(subject);
    let mut best: BTreeMap<Identifier, Capability> = BTreeMap::new();
    for signed in keyhive.delegations_about(subject).await? {
        let (issuer, d): (_, Delegation) = decode_stored(&signed)?;
        let can = if issuer == subject_id {
            d.power
        } else {
            match held.get(&issuer) {
                Some(standing) => d.power.min(*standing),
                None => continue, // a live delegation's issuer has standing
            }
        };
        let who = d.audience;
        match best.get(&who) {
            Some(kept) if kept.can >= can => {}
            _ => {
                best.insert(
                    who,
                    Capability {
                        who,
                        can,
                        proof: JsSignedDelegation(signed),
                    },
                );
            }
        }
    }
    Ok(best.into_values().collect())
}
