use super::offset_seconds::OffsetSeconds;
use std::{
    ops::{Add, Sub},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixTimestamp(pub u64);

impl UnixTimestamp {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
    }

    pub fn now_with_offset(offset: OffsetSeconds) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let adjusted = now as i128 + offset.0 as i128;
        Self(adjusted as u64)
    }
}

impl From<u64> for UnixTimestamp {
    fn from(seconds: u64) -> Self {
        Self(seconds)
    }
}

impl From<UnixTimestamp> for Vec<u8> {
    fn from(ts: UnixTimestamp) -> Self {
        ts.0.to_be_bytes().to_vec()
    }
}

impl Add<OffsetSeconds> for UnixTimestamp {
    type Output = Self;

    fn add(self, rhs: OffsetSeconds) -> Self::Output {
        let big_time = self.0 as i128 + rhs.0 as i128;
        Self(big_time as u64)
    }
}

impl Add<Duration> for UnixTimestamp {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_secs())
    }
}

impl Sub for UnixTimestamp {
    type Output = OffsetSeconds;

    fn sub(self, rhs: Self) -> Self::Output {
        let big_time = self.0 as i128 - rhs.0 as i128;
        OffsetSeconds(big_time as i64)
    }
}

impl Sub<OffsetSeconds> for UnixTimestamp {
    type Output = Self;

    fn sub(self, rhs: OffsetSeconds) -> Self::Output {
        let big_time = self.0 as i128 - rhs.0 as i128;
        Self(big_time as u64)
    }
}

impl Sub<Duration> for UnixTimestamp {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.as_secs())
    }
}
