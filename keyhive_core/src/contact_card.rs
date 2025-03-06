use crate::{
    principal::individual::{op::KeyOp, Individual},
    util::hex,
};

#[derive(Debug)]
pub struct ContactCard(KeyOp);

impl std::fmt::Display for ContactCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContactCard for ",)?;
        hex::bytes_as_hex(self.0.issuer().as_bytes().iter(), f)
    }
}

impl From<KeyOp> for ContactCard {
    fn from(key_op: KeyOp) -> ContactCard {
        ContactCard(key_op)
    }
}

impl<'a> From<&'a ContactCard> for Individual {
    fn from(contact_card: &'a ContactCard) -> Individual {
        Individual::new(contact_card.0.clone())
    }
}

impl From<ContactCard> for Individual {
    fn from(contact_card: ContactCard) -> Individual {
        Individual::new(contact_card.0)
    }
}
