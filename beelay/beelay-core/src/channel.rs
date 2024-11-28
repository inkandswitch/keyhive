//! Pairwise channels.
//!
//! The main types in this module are [`Manager`] and [`Session`].
//! The manager is responsible for managing your signing key, creating and managing many sessions.
//! Sessions track for sending and receiving messages, DH key exchange, and ratcheting.

pub mod ack;
pub mod connect;
pub mod counter_connect;
pub mod dial;
pub mod disconnect;
pub mod hash;
pub mod manager;
pub mod signed;

use chacha20poly1305::{AeadInPlace, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hash::Hash;
use signed::Signed;

pub struct ClientConn(x25519_dalek::EphemeralSecret);
pub struct ClientChannel {
    sender: ed25519_dalek::VerifyingKey,
    secret: [u8; 32],
}
pub struct ServerConn {
    my_id: String,
    secret_swarm_seed: Seed,
}

impl ClientConn {
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        Self(x25519_dalek::EphemeralSecret::random_from_rng(csprng))
    }

    pub fn hello(&self, server_id: String) -> Hello {
        Hello {
            client_pk: (&self.0).into(),
            server_id: Hash::hash(&server_id), // FIXME needs to append our pk?
        }
    }

    pub fn receive_connect(&self, connect: Connect) -> Result<ClientChannel, String> {
        // check client_vk
        // check server_pk

        let shared_secret = self.0.diffie_hellman(&connect.server_pk);

        let mut secret: Vec<u8> = shared_secret.as_bytes().to_vec();
        secret.extend_from_slice(hello.payload.server_id.raw.as_bytes());
        secret.extend_from_slice(hello.verifier.as_bytes());
        let secret = secret.as_slice();

        let mut nonce_buf = [0u8; 24];
        let mut key_preimage_buf = [0u8; 32];
        let mut hasher = blake3::Hasher::new_keyed(shared_secret.as_bytes())
            .update(b"/beelay/handshake/preimages/")
            .update(secret)
            .finalize_xof();
        hasher.fill(&mut nonce_buf);
        hasher.fill(&mut key_preimage_buf);

        let mut secret = [0u8; 32];

        XChaCha20Poly1305::new_from_slice(&key_preimage_buf)
            .expect("take exactly 32 bytes")
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce_buf),
                self.server_id.raw.as_bytes(), // Associated data
                &mut secret,
                &connect.tag,
            )
            .expect("FIXME");

        Ok(ClientChannel { secret })
    }
}

impl ClientChannel {
    pub fn new_message(&self, content: Vec<u8>) -> Message {
        Message::new(self.sender, &self.secret, content)
    }
}

pub struct Seed([u8; 32]);

impl Seed {
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);
        Self(seed)
    }
}

impl ServerConn {
    pub fn new(my_id: String, secret_swarm_seed: Seed) -> Self {
        Self {
            my_id,
            secret_swarm_seed,
        }
    }

    pub fn receive_hello<R: rand::RngCore + rand::CryptoRng>(
        &self,
        hello: Signed<Hello>,
        csprng: &mut R,
    ) -> Connect {
        // FIXME check serverId, key the hash
        if hello.payload.server_id != Hash::hash(&self.my_id) {
            todo!()
        }

        let sk = x25519_dalek::EphemeralSecret::random_from_rng(csprng);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let shared_secret = sk.diffie_hellman(&hello.payload.client_pk);

        let mut secret: Vec<u8> = shared_secret.as_bytes().to_vec();
        secret.extend_from_slice(hello.verifier.as_bytes());
        let secret = secret.as_slice();

        let mut nonce_buf = [0u8; 24];
        let mut key_preimage_buf = [0u8; 32];

        let mut hasher = blake3::Hasher::new_keyed(shared_secret.as_bytes())
            .update(b"/beelay/handshake/preimages/")
            .update(secret)
            .finalize_xof();

        hasher.fill(&mut nonce_buf);
        hasher.fill(&mut key_preimage_buf);

        let mut secret_preimage = self.secret_swarm_seed.0.to_vec();
        secret_preimage.extend_from_slice(hello.payload.client_pk.as_bytes());
        let mut payload: [u8; 32] =
            blake3::derive_key(&"/beelay/handshake/secret/", &secret_preimage);

        let tag = XChaCha20Poly1305::new_from_slice(&key_preimage_buf)
            .expect("take exactly 32 bytes")
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce_buf),
                hello.payload.server_id.raw.as_bytes(), // Associated data
                &mut payload,
            )
            .expect("FIXME");

        Connect {
            client_vk: hello.verifier,
            server_pk: pk,
            encrypted_secret: payload,
            tag,
        }
    }

    pub fn receive_message(&self, message: Message) -> Result<Vec<u8>, String> {
        let mut buf = b"/beelay/message/".to_vec();
        buf.extend_from_slice(message.content.as_slice());

        let mut preimage = self.secret_swarm_seed.0.to_vec();
        preimage.extend_from_slice(message.sender.as_bytes());

        let mac_key: [u8; 32] = blake3::derive_key(&"/beelay/handshake/secret/", &preimage);
        let mac = blake3::keyed_hash(&mac_key, &buf);

        if *mac.as_bytes() != message.mac.0 {
            return Err("Invalid MAC".to_string());
        }

        Ok(message.content)
    }
}

pub struct Hello {
    client_pk: x25519_dalek::PublicKey,
    server_id: Hash<String>,
}

impl From<Hello> for Vec<u8> {
    fn from(hello: Hello) -> Vec<u8> {
        let mut buf = hello.client_pk.as_bytes().to_vec();
        buf.extend(Vec::<u8>::from(hello.server_id));
        buf
    }
}

pub struct Connect {
    client_vk: ed25519_dalek::VerifyingKey, // From signed envelope
    server_pk: x25519_dalek::PublicKey,

    encrypted_secret: [u8; 32],
    tag: Tag,
}

pub struct Message {
    sender: ed25519_dalek::VerifyingKey,
    content: Vec<u8>,
    mac: Mac,
}

// pub struct Sceret

impl Message {
    pub fn new(sender: ed25519_dalek::VerifyingKey, secret: &[u8; 32], content: Vec<u8>) -> Self {
        let mut buf = b"/beelay/message/".to_vec();
        buf.extend_from_slice(content.as_slice());
        let mac = blake3::keyed_hash(&secret, &buf);

        Self {
            sender,
            mac: Mac(*mac.as_bytes()),
            content,
        }
    }
}

pub struct Mac([u8; 32]);
