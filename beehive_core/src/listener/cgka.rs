use crate::{cgka::operation::CgkaOperation, crypto::signed::Signed};
use std::rc::Rc;

// TODO make async
pub trait CgkaListener {
    fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>); // FIXME perhaps an invocation?
}
