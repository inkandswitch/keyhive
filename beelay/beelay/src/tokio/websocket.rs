use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio_util::sync::PollSender;

pub use error::Error;

use crate::{websocket::WsMessage, Forwarding, StreamDirection};

impl crate::Beelay {
    /// Accept a websocket in an axum handler
    ///
    /// This function must be driven to completion to keep the connection alive.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use beelay::{Beelay, Forwarding};
    /// use std::future::IntoFuture;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let beelay = Beelay::builder().spawn_tokio().await;
    ///     let app = axum::Router::new()
    ///         .route("/", axum::routing::get(websocket_handler))
    ///         .with_state(beelay.clone());
    ///     let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    ///     let server = axum::serve(listener, app).into_future();
    ///     tokio::spawn(server);
    /// }
    ///
    /// async fn websocket_handler(
    ///     ws: axum::extract::ws::WebSocketUpgrade,
    ///     axum::extract::State(handle): axum::extract::State<Beelay>,
    /// ) -> axum::response::Response {
    ///     ws.on_upgrade(|socket| handle_socket(socket, handle))
    /// }
    ///
    /// async fn handle_socket(
    ///     socket: axum::extract::ws::WebSocket,
    ///     beelay: Beelay,
    /// ) {
    ///     tokio::spawn(async move {
    ///         if let Err(e) = beelay.accept_axum(socket, Some("0.0.0.0"), Forwarding::DontForward).await {
    ///             tracing::error!("Error running connection: {}", e);
    ///         }
    ///     });
    /// }
    /// ```
    #[cfg(feature = "axum")]
    pub async fn accept_axum<S, H: AsRef<str>>(
        &self,
        stream: S,
        receive_hostname: Option<H>,
        forwarding: Forwarding,
    ) -> Result<(), Error>
    where
        S: Sink<axum::extract::ws::Message, Error = axum::Error>
            + Stream<Item = Result<axum::extract::ws::Message, axum::Error>>
            + Send
            + 'static,
    {
        use futures::TryStreamExt;

        tracing::trace!("accepting websocket connection");

        let stream = stream.map_err(Error::Axum).sink_map_err(Error::Axum);
        self.connect_tokio_websocket(
            stream,
            StreamDirection::Accepting {
                receive_audience: receive_hostname.map(|s| s.as_ref().to_string()),
            },
            forwarding,
        )
        .await
    }

    #[cfg(feature = "tokio")]
    pub(crate) async fn connect_tokio_websocket<S, M>(
        &self,
        stream: S,
        direction: StreamDirection,
        forwarding: Forwarding,
    ) -> Result<(), Error>
    where
        M: Into<WsMessage> + From<WsMessage> + Send + 'static,
        S: Sink<M, Error = Error> + Stream<Item = Result<M, Error>> + Send + 'static,
    {
        // We have to do a bunch of acrobatics here. The `handle_connection` call expects a stream
        // and a sink. However, we need to intercept the stream of websocket messages and if we see
        // a ping we need to immediately send a pong. Intercepting the stream is straightforward,
        // we just filter it and only forward binary messages but as a side effect send pongs back
        // to the server whenever we see a ping. This last part makes the sink side of things
        // tricky though. We can't just use the sink from the filter because we also have to pass
        // the sink to the `connect_stream` call.
        //
        // To get around this we create a channel. We can then create a sink from the sender side
        // of the channel and pass that to `handle_connection` and we can also push to the channel
        // from the filter. Then we create a future which pulls from the other end of the channel
        // and sends to the websocket sink. This is the future that we return from this function.

        let (mut sink, stream) = stream.split();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<WsMessage>(1);

        let msg_stream = stream
            .filter_map::<_, Result<Vec<u8>, Error>, _>({
                let tx = tx.clone();
                move |msg| {
                    let tx = tx.clone();
                    async move {
                        let msg = match msg {
                            Ok(m) => m,
                            Err(e) => return Some(Err(e)),
                        };
                        match msg.into() {
                            WsMessage::Binary(data) => Some(Ok(data)),
                            WsMessage::Close => {
                                tracing::debug!("websocket closing");
                                None
                            }
                            WsMessage::Ping(ping_data) => {
                                let pong_response = WsMessage::Pong(ping_data);
                                tx.send(pong_response).await.ok();
                                None
                            }
                            WsMessage::Pong(_) => None,
                            WsMessage::Text(_) => Some(Err(Error::UnexpectedString)),
                        }
                    }
                }
            })
            .boxed();

        let msg_sink = PollSender::new(tx.clone())
            // This error shouldn't happen because we're holding on to the receiver above but oh
            // well
            .sink_map_err(|_| Error::PollSend)
            .with(|msg: Vec<u8>| futures::future::ready(Ok::<_, Error>(WsMessage::Binary(msg))));

        let handle_stream = async move {
            let connecting = self
                .handle_stream::<Error, _, Error, _>(msg_stream, msg_sink, direction, forwarding);
            connecting.driver.await.map_err(Error::from)
        };

        // Spawn a task to forward messages to the websocket sink
        let mut do_send = Box::pin(
            async move {
                while let Some(msg) = rx.recv().await {
                    if let Err(e) = sink.send(msg.into()).await {
                        tracing::error!(err=?e, "error sending message");
                        return Err(e);
                    }
                }
                Ok(())
            }
            .fuse(),
        );

        futures::select! {
            res = handle_stream.fuse() => {
                res?;
            },
            res = do_send => {
                match res {
                    Err(e) => {
                        tracing::error!(err=?e, "error sending message");
                        return Err(e);
                    }
                    Ok(()) => {
                        tracing::error!("websocket send loop unexpectedly stopped");
                        return Ok(())
                    }
                }
            },
        };
        Ok(())
    }
}

mod error {

    pub enum Error {
        Axum(axum::Error),
        UnexpectedString,
        PollSend,
        Decode(beelay_core::connection::error::Receive),
        DriverStopped,
        Disconnected,
        UnexpectedMessage,
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Error::Axum(e) => write!(f, "axum error: {}", e),
                Error::UnexpectedString => write!(f, "unexpected string message on websocket"),
                Error::PollSend => write!(f, "internal error"),
                Error::Decode(e) => write!(f, "error decoding message: {}", e),
                Error::DriverStopped => write!(f, "the beelay driver task stopped"),
                Error::Disconnected => write!(f, "websocket disconnected"),
                Error::UnexpectedMessage => write!(f, "unexpected message"),
            }
        }
    }

    impl From<crate::error::ConnectionError<Error, Error>> for Error {
        fn from(value: crate::error::ConnectionError<Error, Error>) -> Self {
            match value {
                crate::error::ConnectionError::DriverStopped => Error::DriverStopped,
                crate::error::ConnectionError::Recv(e) => e,
                crate::error::ConnectionError::Send(e) => e,
            }
        }
    }

    impl std::fmt::Debug for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl std::error::Error for Error {}

    impl From<axum::Error> for Error {
        fn from(e: axum::Error) -> Self {
            Error::Axum(e)
        }
    }

    impl<T> From<tokio_util::sync::PollSendError<T>> for Error {
        fn from(_: tokio_util::sync::PollSendError<T>) -> Self {
            Error::PollSend
        }
    }

    impl From<beelay_core::connection::error::Receive> for Error {
        fn from(value: beelay_core::connection::error::Receive) -> Self {
            Self::Decode(value)
        }
    }
}
