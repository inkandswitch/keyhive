use std::future::IntoFuture;

use beelay::{Beelay, Forwarding};
use futures::{pin_mut, FutureExt, StreamExt};
use tokio_util::sync::CancellationToken;

use super::ServeArgs;

pub(super) async fn serve(
    beelay: Beelay,
    ServeArgs {
        websocket_port,
        tcp_port,
    }: ServeArgs,
) {
    let cancel = CancellationToken::new();

    let ws_server = serve_websocket(beelay.clone(), cancel.clone(), websocket_port).fuse();
    pin_mut!(ws_server);
    let tcp_server = serve_tcp(beelay.clone(), cancel.clone(), tcp_port).fuse();
    pin_mut!(tcp_server);

    let interrupted = tokio::signal::ctrl_c().into_future();

    futures::select! {
        _ = interrupted.fuse() => {
            tracing::info!("Interrupted");
            cancel.cancel();
        },
        ws_result = ws_server => {
            tracing::error!("WebSocket listener exited: {:?}", ws_result);
        },
        tcp_result = tcp_server => {
            tracing::error!("TCP listener exited: {:?}", tcp_result);
        },
    };

    tracing::info!("Shutting down");
    let (ws_result, tcp_result) = futures::future::join(ws_server, tcp_server).await;
    ws_result.unwrap();
    tcp_result.unwrap();
}

async fn serve_websocket(
    beelay: Beelay,
    cancel: CancellationToken,
    websocket_port: Option<u16>,
) -> Result<(), std::io::Error> {
    let app = axum::Router::new()
        .route("/", axum::routing::get(websocket_handler))
        .with_state(beelay.clone());
    let ws_listener = if let Some(port) = websocket_port {
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .expect("unable to bind socket")
    } else {
        tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .expect("unable to bind socket")
    };
    let ws_port = ws_listener.local_addr().unwrap().port();
    tracing::info!("WebSocket listening on port {}", ws_port);
    let server = axum::serve(ws_listener, app).into_future();
    futures::select! {
        _ = cancel.cancelled().fuse() => {
            Ok(())
        },
        result = server.fuse() => {
            result
        }
    }
}

async fn websocket_handler(
    ws: axum::extract::ws::WebSocketUpgrade,
    axum::extract::State(beelay): axum::extract::State<beelay::Beelay>,
) -> axum::response::Response {
    ws.on_upgrade(|socket| handle_socket(socket, beelay))
}

async fn handle_socket(socket: axum::extract::ws::WebSocket, beelay: beelay::Beelay) {
    tokio::spawn(async move {
        if let Err(e) = beelay
            .accept_axum(socket, None, Forwarding::DontForward)
            .await
        {
            tracing::error!("Error running connection: {}", e);
        }
    });
}

async fn serve_tcp(
    beelay: Beelay,
    cancel: CancellationToken,
    tcp_port: Option<u16>,
) -> Result<(), std::io::Error> {
    let tcp_listener = if let Some(port) = tcp_port {
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
            .await
            .expect("unable to bind socket")
    } else {
        tokio::net::TcpListener::bind("0.0.0.0:0")
            .await
            .expect("unable to bind socket")
    };
    let tcp_port = tcp_listener.local_addr().unwrap().port();
    tracing::info!("TCP listening on port {}", tcp_port);
    let tcp_server = async move {
        let mut running_connections = futures::stream::FuturesUnordered::new();
        let result = loop {
            futures::select! {
                _ = cancel.cancelled().fuse() => {
                    break Ok(());
                },
                acc = tcp_listener.accept().fuse() => {
                    let (socket, _) = match acc{
                        Ok(s) => s,
                        Err(e) =>{
                            tracing::error!("tcp: error accepting connection: {}", e);
                            break Err(e);
                        }
                    };
                    tracing::info!(source=%socket.peer_addr().unwrap(), "tcp: accepted connection from");
                    let handler = beelay.accept_tokio_io(socket, None, Forwarding::DontForward);
                    running_connections.push(handler);
                },
                conn = running_connections.select_next_some() => {
                    if let Err(e) = conn {
                        tracing::error!("tcp: error running connection: {}", e);
                    }
                }
            }
        };
        while let Some(finished) = running_connections.next().await {
            if let Err(e) = finished {
                tracing::error!("Error running connection: {}", e);
            }
        }
        result
    };
    tcp_server.await
}
