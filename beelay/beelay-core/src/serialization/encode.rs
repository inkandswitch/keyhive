pub(crate) trait Encode {
    fn encode_into(&self, out: &mut Vec<u8>);
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }
}
