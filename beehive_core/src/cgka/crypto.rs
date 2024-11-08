use super::{
    error::CgkaError,
    treemath::{self, TreeNodeIndex, TreeSize},
};
use crate::{
    content::reference::ContentRef,
    crypto::{
        domain_separator::SEPARATOR_STR,
        encrypted::NestedEncrypted,
        share_key::{ShareKey, ShareSecretKey},
        siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::document::Document,
};
/// TODO: Replace relying on these as much as possible with shared, core crypto code.
use aead::OsRng;
use nonempty::NonEmpty;
use x25519_dalek::StaticSecret;

/// Key derivation function
pub(crate) fn kdf(context: &str, last_sk: &ShareSecretKey) -> (ShareKey, ShareSecretKey) {
    let separator = format!("{}{}/beekem-node", SEPARATOR_STR, context);
    let derived_bytes: [u8; 32] = blake3::derive_key(&separator, &last_sk.to_bytes());
    let sk = StaticSecret::from(derived_bytes);
    let pk: x25519_dalek::PublicKey = (&sk).into();
    (pk.into(), sk.into())
}

// FIXME thread through the doc ID
pub(crate) fn derive_secret_from_hash_chain(
    mut secret: ShareSecretKey,
    node_idx: TreeNodeIndex,
    tree_size: TreeSize,
) -> Result<ShareSecretKey, CgkaError> {
    let path_length = treemath::direct_path(node_idx, tree_size).len();
    for _ in 0..path_length {
        (_, secret) = kdf(&"FIXME use doc ID", &secret);
    }
    Ok(secret)
}

pub fn generate_key_pair() -> (ShareKey, ShareSecretKey) {
    let sk = StaticSecret::random_from_rng(OsRng); // TODO thread an RNG around or use getrandpm
    let pk = x25519_dalek::PublicKey::from(&sk);
    (pk.into(), sk.into())
}

pub fn encrypt_nested_secret<T: ContentRef>(
    doc: &Document<T>,
    secret: &ShareSecretKey,
    encrypt_keys: &NonEmpty<(ShareKey, ShareSecretKey)>,
) -> Result<NestedEncrypted<ShareSecretKey>, CgkaError> {
    let mut ciphertext = secret.to_bytes().to_vec();
    let mut nonces: Vec<Siv> = Vec::new();

    for (pk, sk) in encrypt_keys.iter() {
        let nonce = Siv::new(&SymmetricKey::from(sk.to_bytes()), &ciphertext, doc).expect("FIXME");
        nonces.push(nonce.clone());

        sk.derive_symmetric_key(&pk)
            .try_encrypt(nonce, &mut ciphertext)
            .expect("FIXME");
        // .map_err(|e| CgkaError::Encryption(e.to_string()))?;
    }

    todo!()

    // for (_, encrypt_key) in encrypt_keys.iter().skip(1) {
    //     (nonce, encrypted_secret_bytes) = encrypt_bytes(&encrypted_secret_bytes, encrypt_key)?;
    //     nonces.push(nonce);
    // }
    // let encrypted_secret: NestedEncrypted<ShareSecretKey> =
    //     NestedEncrypted::new(nonces, paired_pks, encrypted_secret_bytes);
    // Ok(encrypted_secret)
}

// pub fn generate_shared_key(their_public_key: &ShareKey, my_secret: &SecretKey) -> SecretKey {
//     x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into()
// }

pub fn decrypt_nested_secret(
    encrypted: &NestedEncrypted<ShareSecretKey>,
    decrypt_keys: &[ShareSecretKey],
) -> Result<ShareSecretKey, CgkaError> {
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

    Ok(StaticSecret::from(decrypted_bytes).into())
}

fn decrypt_layer(
    ciphertext: &[u8],
    nonce: &Siv,
    decrypt_key: &ShareSecretKey,
) -> Result<Vec<u8>, CgkaError> {
    let mut decrypted = ciphertext.to_vec();

    SymmetricKey::from(decrypt_key.to_bytes())
        .try_decrypt(*nonce, &mut decrypted)
        .map_err(|e| CgkaError::Decryption(e.to_string()))?;

    Ok(decrypted)
}
