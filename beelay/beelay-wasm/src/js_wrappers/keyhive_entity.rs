use beelay_core::{contact_card::ContactCard, keyhive::KeyhiveEntityId, DocumentId, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum KeyhiveEntity {
    #[serde(rename = "individual")]
    Individual {
        #[serde(with = "crate::js_wrappers::contact_card", rename = "contactCard")]
        contact_card: ContactCard,
    },
    #[serde(rename = "group")]
    Group {
        #[serde(with = "crate::js_wrappers::peer_id")]
        id: PeerId,
    },
    #[serde(rename = "document")]
    Document {
        #[serde(with = "crate::js_wrappers::doc_id")]
        id: DocumentId,
    },
    #[serde(rename = "public")]
    Public,
}

impl From<KeyhiveEntityId> for KeyhiveEntity {
    fn from(value: KeyhiveEntityId) -> Self {
        match value {
            KeyhiveEntityId::Individual(contact_card) => KeyhiveEntity::Individual { contact_card },
            KeyhiveEntityId::Group(peer_id) => KeyhiveEntity::Group { id: peer_id },
            KeyhiveEntityId::Doc(document_id) => KeyhiveEntity::Document { id: document_id },
            KeyhiveEntityId::Public => KeyhiveEntity::Public,
        }
    }
}

impl From<KeyhiveEntity> for KeyhiveEntityId {
    fn from(value: KeyhiveEntity) -> Self {
        match value {
            KeyhiveEntity::Individual { contact_card } => KeyhiveEntityId::Individual(contact_card),
            KeyhiveEntity::Group { id } => KeyhiveEntityId::Group(id),
            KeyhiveEntity::Document { id } => KeyhiveEntityId::Doc(id),
            KeyhiveEntity::Public => KeyhiveEntityId::Public,
        }
    }
}
