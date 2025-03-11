use crate::crypto::share_key::ShareSecretKey;

#[derive(Debug, Clone)]
pub struct NewShareKey<Op> {
    pub new_secret: ShareSecretKey,
    // This is either a RotateKeyOp or an AddKeyOp
    pub op: Op,
}
