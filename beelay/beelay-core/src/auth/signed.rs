use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::hash::{Hash, Hasher};

use crate::{
    deser::{Encode, Parse},
    parse,
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
    pub fn try_sign(payload: T, signer: &SigningKey) -> Result<Self, signature::Error> {
        let to_sign: Vec<u8> = payload.encode();

        Ok(Self {
            verifier: signer.verifying_key(),
            signature: signer.try_sign(to_sign.as_slice())?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signs() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signed = Signed::try_sign("hello", &sk);
        assert!(signed.is_ok());
    }

    #[test]
    fn test_verifies() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signed = Signed::try_sign("hello", &sk).unwrap();
        assert!(signed.verify().is_ok());
    }
}
