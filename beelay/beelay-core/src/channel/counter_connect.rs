use super::{connect::Connect, hash::Hash, signed::Signed};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CounterConnect(pub Hash<Signed<Connect>>);

impl From<CounterConnect> for Vec<u8> {
    fn from(cc: CounterConnect) -> Vec<u8> {
        let mut buf = b"beelay:chan:couterconnect:".to_vec();
        buf.extend(Vec::<u8>::from(cc.0));
        buf
    }
}
