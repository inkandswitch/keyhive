use crate::serialization::{parse, Encode, Parse};

use crate::auth::offset_seconds::OffsetSeconds;
use std::{
    ops::{Add, AddAssign, Sub},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(test, derive(arbitrary::Arbitrary))]
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

impl Encode for UnixTimestamp {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes());
    }
}

impl Parse<'_> for UnixTimestamp {
    fn parse(input: parse::Input<'_>) -> Result<(parse::Input<'_>, Self), parse::ParseError> {
        let (input, seconds) = parse::u64_be(input)?;
        Ok((input, Self(seconds)))
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

impl AddAssign<Duration> for UnixTimestamp {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.as_secs();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTimestampMillis(u128);

impl UnixTimestampMillis {
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
    }

    pub fn new(millis: u128) -> Self {
        Self(millis)
    }

    pub fn as_secs(&self) -> UnixTimestamp {
        UnixTimestamp((self.0 / 1000) as u64)
    }
}

impl From<UnixTimestampMillis> for UnixTimestamp {
    fn from(millis: UnixTimestampMillis) -> Self {
        Self((millis.0 / 1000) as u64)
    }
}

impl AddAssign<Duration> for UnixTimestampMillis {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.as_millis();
    }
}

impl Add<Duration> for UnixTimestampMillis {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs.as_millis())
    }
}

impl Sub<Duration> for UnixTimestampMillis {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        Self(self.0 - rhs.as_millis())
    }
}

impl Sub<UnixTimestampMillis> for UnixTimestampMillis {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        let diff = self.0 as i128 - rhs.0 as i128;
        Duration::from_millis(diff as u64)
    }
}
