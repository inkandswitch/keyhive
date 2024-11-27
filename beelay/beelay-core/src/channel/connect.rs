use super::{dial::Dial, hash::Hash, signed::Signed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect(pub Hash<Signed<Dial>>);

impl From<Connect> for Vec<u8> {
    fn from(connect: Connect) -> Vec<u8> {
        let mut buf = b"beelay:chan:connect:".to_vec();
        buf.extend(&Vec::<u8>::from(connect.0));
        buf
    }
}
