//! Pairwise channels.

use ed25519_dalek::VerifyingKey;

pub mod audience;
pub mod manager;
pub mod message;
pub mod offset_seconds;
pub mod signed;
pub mod unix_timestamp;

#[derive(Debug)]
pub(crate) struct Authenticated<T> {
    pub(crate) from: VerifyingKey,
    pub(crate) content: T,
}

#[cfg(test)]
mod tests {
    use super::*;
    use audience::Audience;
    use manager::Manager;
    use unix_timestamp::UnixTimestamp;

    #[test]
    fn test_round_trip() {
        let now = UnixTimestamp::now();
        let sync_server_id = Audience::service_name("sync.example.com");
        let sync_server_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let sync_server = Manager::new(sync_server_signer, Some(sync_server_id));

        let client_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let client = Manager::new(client_signer, None);

        let msg_content = b"Hello, world!".to_vec();
        let client_msg = client.send(now, sync_server_id, msg_content.clone());

        let received = sync_server.receive_raw(now, client_msg).unwrap();

        assert_eq!(received.content, msg_content);
    }

    #[test]
    fn messages_for_key_of_manager_are_valid() {
        let now = UnixTimestamp::now();
        let sync_server_id = Audience::service_name("sync.example.com");
        let sync_server_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let sync_server = Manager::new(sync_server_signer, Some(sync_server_id));

        let client_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let client = Manager::new(client_signer, None);

        let msg_content = b"Hello, world!".to_vec();
        let client_msg = client.send(now, (&sync_server.signing_key).into(), msg_content.clone());

        let received = sync_server.receive_raw(now, client_msg).unwrap();

        assert_eq!(received.content, msg_content);
    }
}
