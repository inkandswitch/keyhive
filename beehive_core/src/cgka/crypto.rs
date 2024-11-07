use super::{
    error::CgkaError,
    keys::{PublicKey, SecretKey},
    treemath::{self, TreeNodeIndex, TreeSize},
};
use crate::crypto::{
    domain_separator::SEPARATOR_STR, encrypted::NestedEncrypted, siv::Siv,
    symmetric_key::SymmetricKey,
};
/// TODO: Replace relying on these as much as possible with shared, core crypto code.
use aead::OsRng;
use rand::RngCore;
use x25519_dalek::{x25519, StaticSecret};

/// Key derivation function
pub(crate) fn kdf(context: &str, last_sk: &SecretKey) -> (PublicKey, SecretKey) {
    let separator = format!("{}{}", SEPARATOR_STR, context);
    let derived_bytes: [u8; 32] = blake3::derive_key(&separator, last_sk.as_bytes());
    let sk = StaticSecret::from(derived_bytes);
    let pk = PublicKey::from(&sk);
    (pk, sk)
}

pub(crate) fn derive_secret_from_hash_chain(
    mut secret: SecretKey,
    node_idx: TreeNodeIndex,
    tree_size: TreeSize,
) -> Result<SecretKey, CgkaError> {
    let path_length = treemath::direct_path(node_idx, tree_size).len();
    for _ in 0..path_length {
        (_, secret) = kdf(&"FIXME use doc ID", &secret);
    }
    Ok(secret)
}

pub fn generate_key_pair() -> (PublicKey, SecretKey) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (pk, sk)
}

fn encrypt_bytes(bytes: &[u8], encrypt_key: &SecretKey) -> Result<(Siv, Vec<u8>), CgkaError> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut encrypted = bytes.to_vec();
    SymmetricKey::from(encrypt_key.to_bytes())
        .try_encrypt(nonce.into(), &mut encrypted)
        .map_err(CgkaError::Encryption)?;
    Ok((nonce.into(), encrypted))
}

pub fn encrypt_nested_secret(
    secret: &SecretKey,
    encrypt_keys: &[(PublicKey, SecretKey)],
) -> Result<NestedEncrypted<SecretKey>, CgkaError> {
    debug_assert!(!encrypt_keys.is_empty());
    let paired_pks = encrypt_keys.iter().map(|(pk, _)| *pk).collect();
    let mut nonces: Vec<Siv> = Vec::new();
    let (mut nonce, mut encrypted_secret_bytes): (Siv, Vec<u8>) =
        encrypt_bytes(&secret.to_bytes(), &encrypt_keys[0].1)?;
    nonces.push(nonce);
    for (_, encrypt_key) in encrypt_keys.iter().skip(1) {
        (nonce, encrypted_secret_bytes) = encrypt_bytes(&encrypted_secret_bytes, encrypt_key)?;
        nonces.push(nonce);
    }
    let encrypted_secret: NestedEncrypted<SecretKey> =
        NestedEncrypted::new(nonces, paired_pks, encrypted_secret_bytes);
    Ok(encrypted_secret)
}

pub fn generate_shared_key(their_public_key: &PublicKey, my_secret: &SecretKey) -> SecretKey {
    x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into()
}

pub fn decrypt_nested_secret(
    encrypted: &NestedEncrypted<SecretKey>,
    decrypt_keys: &[SecretKey],
) -> Result<SecretKey, CgkaError> {
    debug_assert!(!encrypted.nonces.is_empty());
    debug_assert_eq!(encrypted.nonces.len(), decrypt_keys.len());
    let mut ciphertext = encrypted.ciphertext.clone();
    for (idx, nonce) in encrypted.nonces.iter().enumerate().rev() {
        let decrypt_key = &decrypt_keys[idx];
        ciphertext = decrypt_layer(&ciphertext, nonce, decrypt_key)?;
    }

    let decrypted_bytes: [u8; 32] = ciphertext
        .try_into()
        .map_err(|_e| CgkaError::Decryption("Expected 32 bytes".to_string()))?;

    Ok(StaticSecret::from(decrypted_bytes))
}

fn decrypt_layer(
    ciphertext: &[u8],
    nonce: &Siv,
    decrypt_key: &SecretKey,
) -> Result<Vec<u8>, CgkaError> {
    let mut decrypted = ciphertext.to_vec();
    SymmetricKey::from(decrypt_key.to_bytes())
        .try_decrypt(*nonce, &mut decrypted)
        .map_err(|e| CgkaError::Decryption(e.to_string()));
    Ok(decrypted)
}
