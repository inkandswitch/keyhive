use beelay_core::keyhive::MemberAccess;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum JsAccess {
    Pull,
    Read,
    Write,
    Admin,
}

impl From<MemberAccess> for JsAccess {
    fn from(value: MemberAccess) -> Self {
        match value {
            MemberAccess::Pull => JsAccess::Pull,
            MemberAccess::Read => JsAccess::Read,
            MemberAccess::Write => JsAccess::Write,
            MemberAccess::Admin => JsAccess::Admin,
        }
    }
}

impl From<JsAccess> for MemberAccess {
    fn from(value: JsAccess) -> Self {
        match value {
            JsAccess::Pull => MemberAccess::Pull,
            JsAccess::Read => MemberAccess::Read,
            JsAccess::Write => MemberAccess::Write,
            JsAccess::Admin => MemberAccess::Admin,
        }
    }
}
