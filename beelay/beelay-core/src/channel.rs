//! Pairwise channels.

pub mod client;
pub mod connect;
pub mod encrypted;
pub mod hash;
pub mod hello;
pub mod mac;
pub mod message;
pub mod secret;
pub mod seed;
pub mod server;
pub mod signed;

#[cfg(test)]
mod tests {
    use super::*;
    use client::connecting::Connecting;
    use server::Server;

    #[test]
    fn test_connect_flow() {
        let mut csprng = rand::thread_rng();

        let server_id = "My Awesome Server".to_string();
        let server = Server::generate(&mut csprng, server_id.clone());

        let client_signer = ed25519_dalek::SigningKey::generate(&mut csprng);
        let connecting_client = Connecting::generate(
            &mut csprng,
            ed25519_dalek::VerifyingKey::from(&client_signer),
            server_id,
        );

        let hello = connecting_client.hello(client_signer).unwrap();
        let connect = server.receive_hello(hello, &mut csprng).unwrap();
        let client = connecting_client.receive_connect(connect).unwrap();

        let msg_content = "Hello, world!".as_bytes().to_vec();
        let client_msg = client.message(msg_content.clone());
        let received = server.receive_message(client_msg).unwrap();

        assert_eq!(received, msg_content);

        let next_msg_content = "Hello, another world!".as_bytes().to_vec();
        let next_client_msg = client.message(next_msg_content.clone());
        let next_received = server.receive_message(next_client_msg).unwrap();

        assert_eq!(next_received, next_msg_content);
    }
}
