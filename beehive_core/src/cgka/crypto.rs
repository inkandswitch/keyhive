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

pub fn encrypt_nested_secret<T: ContentRef>(
    doc: &Document<T>,
    secret: &ShareSecretKey,
    encrypt_keys: &NonEmpty<(ShareKey, ShareSecretKey)>,
) -> Result<NestedEncrypted<ShareSecretKey>, CgkaError> {
    let mut ciphertext = secret.to_bytes().to_vec();
    let mut nonces: Vec<Siv> = Vec::new();

    for (pk, sk) in encrypt_keys.iter() {
        let nonce = Siv::new(
            &SymmetricKey::from(sk.to_bytes()),
            &ciphertext,
            doc.doc_id(),
        )
        .expect("FIXME");
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
