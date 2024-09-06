/// FIXME Based on https://kerkour.com/chacha20-blake3

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
        domain_separator: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> XChaCha20Blake3Siv {
        //

        let siv = Siv::new(key, plaintext, domain_separator);

        // subKey := HChaCha20(key, nonce[0:16])
        let chacha20_kdf = chacha20::new(key, &siv.bytes[0..16]);

        // chaCha20Blake3Cipher := chacha20Blake3.New(subKey, nonce[16:24])
        // cipherTextWithTag := chaCha20Blake3Cipher.encrypt(plaintext, additionalData)
        //
        // return cipherTextWithTag

        // subKey [32]byte := chaCha20Kdf.XORKeyStream([16]byte{0x00} || nonce[8:24])
        let subkey = chacha20_kdf.apply_keystream_b2b([0; 16].extend(&mut nonce.bytes[8..24]));

        // chaCha20Blake3Cipher := chacha20Blake3.New(subKey, nonce[24:32])
        let cipher = chacha20::XChaCha20::new_from_slice(subkey); // , &nonce.bytes[24..32]);

        // cipherTextWithTag := chaCha20Blake3Cipher.encrypt(plaintext, additionalData)
        let ciphertext = cipher.encrypt(&plaintext, domain_separator); // FIXME double check

        // return cipherTextWithTag
        XChaCha20Blake3Siv {
            mac: Mac::new(ciphertext.clone(), key, domain_separator),
            ciphertext,
            domain_separator,
        }
    }

    pub fn decrypt(
        &self,
        key: &[u8; 32],
        domain_separator: Vec<u8>,
    ) -> Result<Vec<u8>, &'static str> {
        let expected_mac = Mac::new(self.ciphertext.clone(), key, domain_separator);

        if expected_mac.bytes != self.mac.bytes {
            return Err("Invalid MAC");
        }

        let nonce = Siv::new(key, self.ciphertext.clone(), domain_separator);
        let plaintext = chacha20::decrypt(key, &nonce.bytes, &self.ciphertext);

        Ok(plaintext)
    }
}

impl Siv {
    /// Misuse resistent nonce
    /// FIXME function name?
    pub fn new(key: &[u8; 32], mut plaintext: Vec<u8>, mut domain_separator: Vec<u8>) -> Siv {
        Siv {
            bytes: *blake3::keyed_hash(key, plaintext.append(&mut domain_separator)).as_bytes(),
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
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
