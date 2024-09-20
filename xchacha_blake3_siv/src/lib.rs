/// FIXME Based on https://kerkour.com/chacha20-blake3
use cipher::KeyIvInit;
use cipher::StreamCipher;

pub struct Siv {
    pub bytes: [u8; 32],
}

pub struct Mac {
    pub bytes: [u8; 32],
}

pub struct XChaCha20Blake3Siv {
    mac: Mac,
    domain_separator: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl XChaCha20Blake3Siv {
    pub fn new(
        key: &[u8; 32],
        // FIXME Per the BLAKE3 docs: Given cryptographic key material of any length and a context string of any length, this function outputs a 32-byte derived subkey. The context string should be hardcoded, globally unique, and application-specific. A good default format for such strings is "[application] [commit timestamp] [purpose]", e.g., "example.com 2019-12-25 16:18:03 session tokens v1".
        mut domain_separator: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> XChaCha20Blake3Siv {
        //

        let siv = Siv::new(key, plaintext.clone(), domain_separator.clone());

        // subKey := HChaCha20(key, nonce[0:16])
        // FIXME actually use HChaCha instead of BLAKE3
        let mut key_vec = key.to_vec();
        key_vec.extend(&siv.bytes[0..16]);
        let subkey: [u8; 32] = blake3::derive_key(
            std::str::from_utf8(domain_separator.clone().as_slice()).expect("FIXME"),
            key_vec.as_slice(),
        );

        // chaCha20Blake3Cipher := chacha20Blake3.New(subKey, nonce[16:24])
        let mut cipher =
            chacha20::XChaCha20::new_from_slices(subkey.as_slice(), &siv.bytes[16..24])
                .expect("FIXME");

        // cipherTextWithTag := chaCha20Blake3Cipher.encrypt(plaintext, additionalData)
        domain_separator.extend(plaintext);
        let input = domain_separator.as_slice();

        let mut ciphertext_buf = vec![];
        cipher
            .apply_keystream_b2b(&input, &mut ciphertext_buf)
            .expect("FIXME");

        // return cipherTextWithTag
        XChaCha20Blake3Siv {
            mac: Mac::new(ciphertext_buf.clone(), key, domain_separator.clone()),
            ciphertext: ciphertext_buf,
            domain_separator,
        }
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let expected_mac = Mac::new(self.ciphertext.clone(), key, self.domain_separator.clone());

        if expected_mac.bytes != self.mac.bytes {
            return Err("Invalid MAC");
        }

        let nonce = Siv::new(key, self.ciphertext.clone(), self.domain_separator.clone());
        let mut chacha = chacha20::XChaCha20::new_from_slices(
            blake3::derive_key(
                std::str::from_utf8(key).expect("FIXME"),
                &nonce.bytes[0..16],
            )
            .as_slice(),
            &nonce.bytes[16..24],
        )
        .expect("FIXME");

        let mut plaintext_buf = vec![];
        chacha
            .apply_keystream_b2b(self.ciphertext.as_slice(), &mut plaintext_buf)
            .expect("FIXME"); // FIXME (&nonce.bytes, &self.ciphertext);

        // FIXME more checks?

        Ok(plaintext_buf)
    }
}

impl Siv {
    /// Misuse resistent nonce
    /// FIXME function name?
    pub fn new(key: &[u8; 32], plaintext: Vec<u8>, domain_separator: Vec<u8>) -> Siv {
        let mut foo = plaintext.clone();
        foo.append(&mut domain_separator.clone());

        Siv {
            bytes: *blake3::keyed_hash(key, &foo).as_bytes(),
        }
    }
}

impl Mac {
    pub fn new(mut ciphertext: Vec<u8>, key: &[u8; 32], mut domain_separator: Vec<u8>) -> Mac {
        let ds_len_bytes = domain_separator.len().to_le_bytes();
        let ct_len_bytes = ciphertext.len().to_le_bytes();

        domain_separator.append(&mut ciphertext);
        domain_separator.append(&mut ds_len_bytes.to_vec());
        domain_separator.append(&mut ct_len_bytes.to_vec());

        Mac {
            bytes: *blake3::keyed_hash(key, &domain_separator).as_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(4, 4);
    }
}
