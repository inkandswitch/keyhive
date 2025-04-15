use std::{
    future::Future,
    sync::{atomic::AtomicBool, Arc},
    task::{Context, Poll},
};

use futures::{
    task::{waker, ArcWake, LocalFutureObj},
    FutureExt,
};

/// A very simple "executor" which just drives a single future.
pub(crate) struct LocalExecutor {
    running: Option<LocalFutureObj<'static, ()>>,
}

struct WakeThis {
    woken: AtomicBool,
}

impl ArcWake for WakeThis {
    fn wake_by_ref(arc_self: &std::sync::Arc<Self>) {
        arc_self
            .woken
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl LocalExecutor {
    /// Create a new `LocalExecutor` which will  drive the given Future until completion
    pub(crate) fn spawn<Fut: Future<Output = ()> + 'static>(fut: Fut) -> Self {
        let fut_obj = LocalFutureObj::new(Box::new(fut));
        Self {
            running: Some(fut_obj),
        }
    }

    /// Run the spawned future until it can't make progress
    pub(super) fn run_until_stalled(&mut self) {
        let wake_this = Arc::new(WakeThis {
            woken: AtomicBool::new(false),
        });
        let waker = waker(wake_this.clone());
        loop {
            let Some(running) = &mut self.running else {
                return;
            };
            let mut cx = Context::from_waker(&waker);

            let pool_ret = running.poll_unpin(&mut cx);
            match pool_ret {
                Poll::Ready(()) => {
                    // Make sure we don't poll the future once it's completed
                    self.running = None;
                    return;
                }
                Poll::Pending => {
                    // Handle futures which call wake while we're polling them (as FuturesUnordered does)
                    let woken = wake_this.woken.load(std::sync::atomic::Ordering::SeqCst);
                    if woken {
                        wake_this
                            .woken
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        continue;
                    } else {
                        // We're stalled for now.
                        return;
                    }
                }
            }
        }
    }
}
