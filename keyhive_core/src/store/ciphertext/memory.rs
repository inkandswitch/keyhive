use dupe::Dupe;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

use crate::{content::reference::ContentRef, crypto::encrypted::EncryptedContent};

#[derive(Debug, Clone, Dupe, PartialEq, Eq)]
pub struct MemoryCiphertextStore<T: ContentRef, P> {
    pub store: Rc<RefCell<HashMap<T, EncryptedContent<P, T>>>>,
}

impl<T: ContentRef, P> MemoryCiphertextStore<T, P> {
    pub fn new() -> Self {
        MemoryCiphertextStore {
            store: Rc::new(RefCell::new(HashMap::new())),
        }
    }
}
