// !@ TODO
// use crate::{cgka::{beekem::BeeKem, Cgka}, crypto::{encrypted::Encrypted, share_key::{ShareKey, ShareSecretKey}}, principal::identifier::Identifier};

// use super::id::DocumentId;

// pub(crate) struct DocumentEncryption {
//     cgka: Cgka,
//     current_secret: Option<ShareSecretKey>,
// }

// impl DocumentEncryption {
//     pub(crate) fn new(
//         members: Vec<(Identifier, ShareKey)>,
//         doc_id: DocumentId,
//         id: Identifier,
//         pk: ShareKey,
//         sk: ShareSecretKey,
//     ) -> Self {
//         let cgka = Cgka::new(
//             members, doc_id, id, pk, sk,
//         ).expect("FIXME");
//         let current_secret = Some(cgka.secret().expect("Cgka to initialize with secret"));
//         Self {
//             cgka,
//             current_secret,
//         }
//     }

//     pub(crate) fn from_tree(tree: BeeKem, id: Identifier, pk: ShareKey) -> Self {
//         let cgka = Cgka::from_tree(id, pk, tree);
//         let current_secret = if cgka.has_secret() {
//             Some(cgka.secret().expect("secret to exist"))
//         } else {
//             None
//         };
//         Self {
//             cgka,
//             current_secret,
//         }
//     }

//     pub(crate) fn pcs_update(&mut self, pk: ShareKey, sk: ShareSecretKey) {
//         let id = self.cgka.owner_id;
//         self.cgka.update(id, pk, sk).expect("FIXME");
//         self.current_secret = Some(self.cgka.secret().expect("secret after PCS update"));
//     }

//     pub(crate) fn encrypt(&mut self, thing_to_encrypt: ShareSecretKey) -> Encrypted<ShareSecretKey> {
//         let encryption_secret = if let Some(secret) = self.current_secret {
//             let next_secret = secret.ratchet_forward();
//             self.current_secret = Some(next_secret.clone());
//             next_secret
//         } else {
//             let sk = ShareSecretKey::generate();
//             let pk = sk.share_key();
//             self.pcs_update(pk, sk);
//             self.current_secret.expect("secret after PCS update")
//         };

//         encryption_secret

//         let key: SymmetricKey = ;

//         let nonce =
//             Siv::new(&key, message.as_slice(), doc.doc_id()).map_err(ShareError::SivError)?;
//         key.try_encrypt(nonce, &mut message)
//             .map_err(ShareError::EncryptionFailed)?;

//         Ok(Encrypted::new(nonce.into(), message))

//     }
// }
