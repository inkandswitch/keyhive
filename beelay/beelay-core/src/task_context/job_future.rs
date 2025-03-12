use std::future::Future;

use futures::{channel::oneshot, FutureExt};

pub(crate) struct JobFuture<T>(pub(crate) oneshot::Receiver<T>);

impl<T> Future for JobFuture<T> {
    type Output = T;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.0.poll_unpin(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(result),
            std::task::Poll::Ready(Err(_)) => {
                tracing::debug!(
                    "polling a cancelled JobFuture, the whole task should be dropped shortly"
                );
                std::task::Poll::Pending
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
