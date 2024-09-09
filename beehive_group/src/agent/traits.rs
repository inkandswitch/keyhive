// FIXME Identifiable? Pricipal?
pub trait Agent {
    fn public_key(&self) -> [u8; 32];
}
