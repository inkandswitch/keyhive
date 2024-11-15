#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HangUp;

impl From<HangUp> for Vec<u8> {
    fn from(_: HangUp) -> Self {
        b"beelay:chan:hangup".to_vec()
    }
}
