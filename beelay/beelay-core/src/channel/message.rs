#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message(pub Vec<u8>);

impl From<Message> for Vec<u8> {
    fn from(msg: Message) -> Vec<u8> {
        let mut v = b"beelay:chan:msg:".to_vec();
        v.extend(msg.0);
        v
    }
}
