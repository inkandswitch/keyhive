use ed25519_dalek::{Signature, VerifyingKey};
use keyhive_core::crypto::{signer::async_signer::AsyncSigner, verifiable::Verifiable};
use std::hash::{Hash, Hasher};

use crate::{
    serialization::{parse, Encode, Parse},
    Signer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signed<T> {
    pub payload: T,
    pub verifier: VerifyingKey,
    pub signature: Signature,
}

#[cfg(test)]
impl<'a, T> arbitrary::Arbitrary<'a> for Signed<T>
where
    T: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let key_bytes = u.arbitrary::<[u8; 32]>()?;
        let signer = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let signature_bytes = u.arbitrary::<[u8; 64]>()?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        let payload = u.arbitrary::<T>()?;
        Ok(Self {
            payload,
            verifier: signer.verifying_key(),
            signature,
        })
    }
}

impl<T: Clone> Signed<T>
where
    T: Encode,
{
    pub async fn try_sign(signer: Signer, payload: T) -> Result<Self, signature::Error> {
        let to_sign: Vec<u8> = payload.encode();

        let signature = signer
            .try_sign_bytes_async(&to_sign)
            .await
            .map_err(signature::Error::from_source)?;

        Ok(Self {
            verifier: signer.verifying_key(),
            signature,
            payload,
        })
    }

    pub fn verify(&self) -> Result<(), signature::Error> {
        let msg: Vec<u8> = self.payload.encode();
        self.verifier.verify_strict(msg.as_slice(), &self.signature)
    }
}

impl<'a, T: for<'b> Parse<'b> + 'static> Parse<'a> for Signed<T> {
    fn parse(input: parse::Input<'a>) -> Result<(parse::Input<'a>, Self), parse::ParseError> {
        input.parse_in_ctx("Signed", |input| {
            let (input, payload_bytes) = input.parse_in_ctx("payload_bytes", parse::slice)?;
            let payload_input = parse::Input::new(payload_bytes);
            let payload = match T::parse(payload_input) {
                Ok((i, m)) => {
                    if !i.is_empty() {
                        Err(input.error("decoding did not consume all bytes of payload"))
                    } else {
                        Ok(m)
                    }
                }
                Err(e) => Err(input.error(format!("failed to parse payload: {}", e))),
            }?;

            let (input, verifier_bytes) = input.parse_in_ctx("verifier", parse::arr::<32>)?;
            let verifier = VerifyingKey::from_bytes(&verifier_bytes)
                .map_err(|e| input.error(format!("invalid verifier key: {}", e)))?;

            let (input, signature_bytes) = input.parse_in_ctx("signature", parse::arr::<64>)?;
            let signature = Signature::from(signature_bytes);

            Ok((
                input,
                Self {
                    payload,
                    verifier,
                    signature,
                },
            ))
        })
    }
}

impl<T: Encode> Encode for Signed<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        self.payload.encode_into(&mut payload);
        payload.encode_into(out);
        out.extend_from_slice(self.verifier.as_bytes());
        out.extend_from_slice(self.signature.to_bytes().as_slice());
    }
}

impl<T: Encode> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.payload.encode().hash(state);
        self.verifier.as_bytes().hash(state);
        self.signature.to_bytes().hash(state);
    }
}
