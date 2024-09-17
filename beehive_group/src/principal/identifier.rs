// FIXME move to ActorId?

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Identifier {
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.verifying_key
            .as_bytes()
            .partial_cmp(&other.verifying_key.as_bytes())
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.verifying_key
            .as_bytes()
            .cmp(&other.verifying_key.as_bytes())
    }
}

impl From<ed25519_dalek::VerifyingKey> for Identifier {
    fn from(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl Identifier {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }
}

// #[derive(Debug, Clone, Hash)]
// pub struct Identifier<T> {
//     pub verifying_key: ed25519_dalek::VerifyingKey,
//     _phantom: std::marker::PhantomData<T>,
// }
//
// impl<T> PartialEq for Identifier<T> {
//     fn eq(&self, other: &Self) -> bool {
//         self.verifying_key.as_bytes() == other.verifying_key.as_bytes()
//     }
// }
//
// impl<T> Eq for Identifier<T> {}
//
// impl<T> PartialOrd for Identifier<T> {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.verifying_key
//             .as_bytes()
//             .partial_cmp(&other.verifying_key.as_bytes())
//     }
// }
//
// impl<T> Ord for Identifier<T> {
//     fn cmp(&self, other: &Self) -> std::cmp::Ordering {
//         self.verifying_key
//             .as_bytes()
//             .cmp(&other.verifying_key.as_bytes())
//     }
// }
