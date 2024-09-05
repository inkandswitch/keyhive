pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Nonce {
    pub bytes: [u8; 32],
}

pub struct Mac {
    pub bytes: [u8; 32],
}

impl Nonce {
    /// Misuse resistent nonce
    /// FIXME function name?
    pub fn new(key: &[u8; 32], plaintext: Vec<u8>, domain_separator: Vec<u8>) -> Nonce {
        Nonce {
            bytes: blake3::keyed_hash(key, plaintext.append(&mut domain_separator)).as_bytes(),
        }
    }
}

pub fn mac(key: [u8; 32], domain_separator: Vec<u8>) -> Mac {
    // pub fn keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash
    let mac: blake3::Hash = blake3::keyed_hash(key, &domain_separator);

    Mac {
        bytes: mac.as_bytes(),
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
