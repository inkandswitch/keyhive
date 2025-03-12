use futures::Future;
use std::cell::RefCell;
use std::collections::HashMap;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

#[derive(Clone)]
pub(crate) struct Stopper(Arc<StopState>);

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct StopWaiterId(u64);

static LAST_STOP_WAITER_ID: AtomicU64 = AtomicU64::new(0);

impl StopWaiterId {
    fn new() -> Self {
        Self(LAST_STOP_WAITER_ID.fetch_add(1, Ordering::Relaxed))
    }
}

struct StopState {
    stopped: AtomicBool,
    waiters: Rc<RefCell<HashMap<StopWaiterId, Waker>>>,
}

impl Stopper {
    pub(super) fn new() -> Self {
        Self(Arc::new(StopState {
            stopped: AtomicBool::new(false),
            waiters: Rc::new(RefCell::new(HashMap::new())),
        }))
    }

    pub(crate) fn stop(&self) {
        self.0.stopped.store(true, Ordering::Release);
        for (_, waker) in self.0.waiters.borrow_mut().drain() {
            waker.wake();
        }
    }

    pub(crate) fn stopped(&self) -> Stopped {
        Stopped {
            state: self.0.clone(),
            waiter_id: StopWaiterId::new(),
        }
    }
}

pub(crate) struct Stopped {
    state: Arc<StopState>,
    waiter_id: StopWaiterId,
}

impl Future for Stopped {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.stopped.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            self.state
                .waiters
                .borrow_mut()
                .insert(self.waiter_id, cx.waker().clone());
            if self.state.stopped.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
}

impl Drop for Stopped {
    fn drop(&mut self) {
        self.state.waiters.borrow_mut().remove(&self.waiter_id);
    }
}
