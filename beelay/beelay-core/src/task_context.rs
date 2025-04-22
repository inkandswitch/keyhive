use std::{cell::RefCell, future::Future, rc::Rc};

use crate::Signer;
use crate::{state::State, UnixTimestampMillis};

mod requests;
pub(crate) use requests::{Requests, SessionRpcError};
mod storage;
pub(crate) use storage::sedimentree::{DocStorage, Error as SedimentreeStorageError};
pub(crate) use storage::Storage;
mod job_future;
pub(crate) use job_future::JobFuture;

pub(crate) struct TaskContext<R: rand::Rng + rand::CryptoRng> {
    now: Rc<RefCell<UnixTimestampMillis>>,
    state: Rc<RefCell<State<R>>>,
    io_handle: crate::io::IoHandle,
    stopper: crate::stopper::Stopper,
}

impl<R: rand::Rng + rand::CryptoRng> std::clone::Clone for TaskContext<R> {
    fn clone(&self) -> Self {
        Self {
            now: self.now.clone(),
            state: self.state.clone(),
            io_handle: self.io_handle.clone(),
            stopper: self.stopper.clone(),
        }
    }
}

impl<R: rand::Rng + rand::CryptoRng> TaskContext<R> {
    pub(crate) fn new(
        now: Rc<RefCell<UnixTimestampMillis>>,
        state: Rc<RefCell<State<R>>>,
        io_handle: crate::io::IoHandle,
        stopper: crate::stopper::Stopper,
    ) -> Self {
        Self {
            now,
            state: state.clone(),
            io_handle,
            stopper,
        }
    }

    pub(crate) fn now(&self) -> UnixTimestampMillis {
        *self.now.borrow()
    }

    pub(crate) fn io(&self) -> &crate::io::IoHandle {
        &self.io_handle
    }

    pub(crate) fn state(&self) -> crate::state::StateAccessor<'_, R> {
        crate::state::StateAccessor::new(&self.state)
    }

    pub(crate) fn signer(&self) -> Signer {
        self.state.borrow().signer()
    }

    pub(crate) fn stopping(&self) -> impl Future<Output = ()> {
        self.stopper.stopped()
    }

    pub(crate) fn requests(&self) -> Requests<'_, R> {
        Requests::new(self.state(), &self.now)
    }

    pub(crate) fn storage(&self) -> Storage<'_> {
        Storage::new(&self.io_handle)
    }
}
