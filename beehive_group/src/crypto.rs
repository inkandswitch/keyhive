use std::marker::PhantomData;

pub struct Signed<T> {
    pub payload: T,
    pub signer: ed25519_dalek::VerifyingKey,
    pub signature: ed25519_dalek::Signature,
}

pub struct Encrypted<T> {
    pub nonce: [u8; 24],
    // FIXME pub additional_data
    pub ciphertext: Vec<u8>,
    pub _phantom: PhantomData<T>, // FIXME not public
}
