pub struct Agent {
    public_key: [u8; 32],
}

pub struct Admin();

pub struct Append {

};

pub struct Read();

pub struct Pull();

pub enum Capability {
    Admin, // FIXME ... do we need this, or is it just an unresirtcted wirter?
    Write,
    Read,
    Pull,
}

pub enum BeehiveOp {
    Delegate {
        who: PublicKey,
        what: Capability
    },

    RevokeAgent {
        // FIXME should be the specific cap, not user?
        who: PublicKey
    }
}

/// Materialized gorup
pub struct Group {
    pub id: PublicKey,
    pub delegates: BTreeMap<PublicKey, Delegate>,
}

// FIXME switch to a trait
impl Agent {
    fn get_caps(&self) -> BTreeMap<Agent, Capability> {
        todo!()
    }
}

pub struct Document {
    pub group: Group,
    pub content: Vec<u8>, // FIXME automerge content
}
