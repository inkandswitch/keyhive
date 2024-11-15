//! Pairwise channels.

pub mod manager;
pub mod message;
pub mod node_id;
pub mod offset_seconds;
pub mod signed;
pub mod unix_timestamp;

#[cfg(test)]
mod tests {
    use super::*;
    use manager::Manager;

    #[test]
    fn test_round_trip() {
        let sync_server_id = "sync.example.com".into();
        let sync_server_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let sync_server = Manager::new(sync_server_signer, Some(sync_server_id));

        let client_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let client = Manager::new(client_signer, None);

        let msg_content = b"Hello, world!".to_vec();
        let client_msg = client
            .send_message(sync_server_id, msg_content.clone(), None)
            .unwrap();

        let received = sync_server.receive_message(client_msg).unwrap();

        assert_eq!(received, msg_content);
    }
}
