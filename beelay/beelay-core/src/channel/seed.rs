#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed(pub(crate) [u8; 32]);

impl Seed {
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);
        Self(seed)
    }
}
