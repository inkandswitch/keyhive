use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash<T> {
    pub raw: blake3::Hash,
    _phantom: PhantomData<T>,
}

impl<T: Clone> From<&T> for Hash<T>
where
    Vec<u8>: From<T>,
{
    fn from(t: &T) -> Self {
        Self {
            raw: blake3::hash(Vec::<u8>::from(t.clone()).as_slice()),
            _phantom: PhantomData,
        }
    }
}

impl<T> From<Hash<T>> for Vec<u8> {
    fn from(hash: Hash<T>) -> Vec<u8> {
        hash.raw.as_bytes().to_vec()
    }
}
