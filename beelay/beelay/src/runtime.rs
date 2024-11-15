use std::{any::Any, sync::Arc};

use futures::Future;

pub trait RuntimeHandle: Send + Sync + 'static {
    type JoinError: JoinError + std::error::Error + Send + 'static;
    type JoinHandle<O: Send + 'static>: Future<Output = Result<O, Self::JoinError>> + Send + 'static;
    fn spawn<F: Future<Output = O> + Send + 'static, O: Send + 'static>(
        &self,
        f: F,
    ) -> Self::JoinHandle<O>;
}

pub trait JoinError {
    fn is_panic(&self) -> bool;
    fn into_panic(self) -> Box<dyn Any + Send + 'static>;
}

impl<T: JoinError> JoinError for Box<T> {
    fn is_panic(&self) -> bool {
        self.as_ref().is_panic()
    }

    fn into_panic(self) -> Box<dyn Any + Send + 'static> {
        (*self).into_panic()
    }
}

impl<R: RuntimeHandle> RuntimeHandle for Arc<R> {
    type JoinError = R::JoinError;
    type JoinHandle<O: Send + 'static> = R::JoinHandle<O>;

    fn spawn<F: Future<Output = O> + Send + 'static, O: Send + 'static>(
        &self,
        f: F,
    ) -> Self::JoinHandle<O> {
        self.as_ref().spawn(f)
    }
}

#[cfg(feature = "tokio")]
mod tokio_runtime {
    use super::*;
    use tokio::task::JoinError as TokioJoinError;

    impl RuntimeHandle for tokio::runtime::Handle {
        type JoinError = TokioJoinError;
        type JoinHandle<O: Send + 'static> = tokio::task::JoinHandle<O>;

        fn spawn<F: Future<Output = O> + Send + 'static, O: Send + 'static>(
            &self,
            f: F,
        ) -> Self::JoinHandle<O> {
            tokio::runtime::Handle::spawn(self, f)
        }
    }

    impl JoinError for TokioJoinError {
        fn is_panic(&self) -> bool {
            TokioJoinError::is_panic(self)
        }

        fn into_panic(self) -> Box<dyn Any + Send + 'static> {
            TokioJoinError::into_panic(self)
        }
    }
}
