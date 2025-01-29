use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use std::rc::Rc;

pub trait CgkaListener {
    fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>);
}
