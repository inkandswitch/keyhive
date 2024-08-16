use std::{io::Write, path::Path, str::FromStr};

use beelay::{Beelay, CommitOrBundle, DocumentId};
use clap::Parser;
use futures::{future::FutureExt, pin_mut};
use peer_url::PeerUrl;
use tracing_subscriber::EnvFilter;

mod peer_url;
mod serve;

#[derive(clap::Parser)]
struct Args {
    #[clap(short, long, global = true)]
    data_dir: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, clap::Subcommand)]
enum Command {
    Serve(ServeArgs),
    Load { doc_id: String },
    Pull(PullArgs),
}

#[derive(Clone, Debug, clap::Args)]
struct ServeArgs {
    #[clap(short, long)]
    websocket_port: Option<u16>,
    #[clap(short, long)]
    tcp_port: Option<u16>,
}

#[derive(Clone, Debug, clap::Args)]
struct PullArgs {
    #[clap(short = 'f', long = "from")]
    peer_url: peer_url::PeerUrl,
    #[clap(short = 'd', long = "dag")]
    doc_id: DocumentId,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info")))
        .init();
    let args = Args::parse();
    let beelay = match args.data_dir {
        Some(data_dir) => {
            let storage_dir = data_dir.join("storage");
            let creds_dir = data_dir.join("creds");
            let creds = match load_creds(&creds_dir) {
                Ok(creds) => creds,
                Err(e) => {
                    eprintln!("Error loading credentials: {}", e);
                    std::process::exit(1);
                }
            };
            let beelay = beelay::Beelay::builder()
                .with_storage(beelay::tokio::FsStorage::open(storage_dir).unwrap())
                .with_signing_key(creds)
                .spawn_tokio()
                .await;
            tracing::info!("Peer id is: {}", beelay.peer_id());
            beelay
        }
        None => beelay::Beelay::builder().spawn_tokio().await,
    };
    match args.command {
        Command::Serve(serve_args) => serve::serve(beelay, serve_args).await,
        Command::Load { doc_id } => load(beelay, doc_id).await,
        Command::Pull(pull_args) => pull(beelay, pull_args).await,
    }
}

async fn load(mut beelay: Beelay, doc_id: String) {
    let Ok(doc_id) = DocumentId::from_str(doc_id.as_ref()) else {
        eprintln!("Invalid doc id: {}", doc_id);
        std::process::exit(1);
    };
    let doc = match beelay.load_doc(doc_id).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error loading doc: {}", e);
            std::process::exit(1);
        }
    };
    tokio::task::spawn_blocking(move || {
        for commit in doc.unwrap_or_default() {
            match commit {
                CommitOrBundle::Commit(commit) => {
                    std::io::stdout().write_all(commit.contents()).unwrap();
                }
                CommitOrBundle::Bundle(b) => {
                    std::io::stdout().write_all(b.bundled_commits()).unwrap();
                }
            }
        }
    })
    .await
    .unwrap();
}

async fn pull(beelay: Beelay, PullArgs { peer_url, doc_id }: PullArgs) {
    match peer_url {
        PeerUrl::Tcp(addr, peer_id) => {
            let conn = tokio::net::TcpStream::connect(addr)
                .await
                .expect("unable to connect to peer");
            let mut pull_beelay = beelay.clone();
            let conn = beelay.connect_tokio_io(conn, peer_id.into(), beelay::Forwarding::Forward);
            let do_pull = async move {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                pull_beelay.sync_doc(doc_id).await
            };
            pin_mut!(do_pull);
            futures::select! {
                result = do_pull.fuse() => {
                    if let Err(e) = result {
                        eprintln!("Error pulling: {}", e);
                        std::process::exit(1);
                    }
                },
                conn_result = conn.fuse() => {
                    if let Err(e) = conn_result {
                        eprintln!("Error connecting: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        PeerUrl::WebSocket(_, _) => todo!(),
    }
}

fn load_creds(creds_dir: &Path) -> eyre::Result<ed25519_dalek::SigningKey> {
    let signing_key_path = creds_dir.join("signing_key");
    if !creds_dir.exists() {
        std::fs::create_dir_all(&creds_dir)?;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        std::fs::write(signing_key_path, signing_key.to_bytes())?;
        Ok(signing_key)
    } else {
        let key_raw = std::fs::read(signing_key_path)?;
        let key_arr =
            <[u8; 32]>::try_from(key_raw).map_err(|_| eyre::eyre!("failed to parse key bytes"))?;
        let secret_key = ed25519_dalek::SecretKey::from(key_arr);
        Ok(ed25519_dalek::SigningKey::from(secret_key))
    }
}
