//! A self-contained capability certificate.

// use crate::{
//     access::Access,
//     crypto::signed::Signed,
//     principal::{
//         agent::Agent, group::operation::delegation::Delegation, individual::Individual,
//         membered::Membered,
//     },
// };
//
// /// A self-contained capability "certificate".
// ///
// /// Contains all of the information needed to prove a delegation.
// #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// pub struct Capability<I, T> {
//     /// Which [`Document`] or [`Group`] this `Capablity` grants rights over.
//     pub subject: Membered,
//
//     /// The [`Access`] level granted by this `Capability`.
//     pub can: Access,
//
//     /// The [`Agent`] that this `Capability` is granted to.
//     pub delegate: Agent,
//
//     /// The proof that backs the delegation.
//     ///
//     /// NOTE: the `delegate` of the [`Delegation`] must be the signer of this `Capability`.
//     pub proof: Signed<Delegation<I, T>,
// }
//
// impl<I, T> Capability<I, T> {
//     /// Get the [`Individual`] that delegated this `Capability`.
//     pub fn delegator(&self) -> Individual {
//         self.proof.verifying_key.clone().into()
//     }
// }
