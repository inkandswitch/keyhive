#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ack;

impl From<Ack> for Vec<u8> {
    fn from(_: Ack) -> Vec<u8> {
        b"beelay:chan:ack".to_vec()
    }
}
