//! BLAKE3 key-derivation contexts.
//!
//! Every `derive_key` in Keyhive takes its context from here, so the contexts
//! can be reviewed in one place and no two derivations share one. A context
//! is `/keyhive/<area>/<purpose>/v<N>/<YYYY-MM-DD>`: general to specific, with
//! the version belonging to the context, and the date the day that version
//! was introduced. BLAKE3 asks for contexts that are "hardcoded, globally
//! unique, and application-specific"; the date makes them unique for all
//! time. A new version gets a new date.
//!
//! The shape, and that the contexts differ, are checked at compile time.

/// A BLAKE3 key-derivation context: one per derivation.
///
/// ```
/// use keyhive_crypto::context::Context;
///
/// assert_eq!(
///     Context::CONTENT_NONCE_KEY.as_str(),
///     "/keyhive/content/nonce-key/v1/2026-10-31"
/// );
/// assert_ne!(
///     Context::CONTENT_NONCE_KEY.derive_key(&[0; 32]),
///     Context::SEAL_NONCE_KEY.derive_key(&[0; 32])
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Context(&'static str);

impl Context {
    /// The key an inviter seals root secrets to an invitee under, from their
    /// X25519 exchange.
    pub const CGKA_INVITATION_KEY: Self = Self::new("/keyhive/cgka/invitation-key/v1/2026-10-31");

    /// The key a BeeKEM node secret is sealed under, from the X25519 exchange
    /// between its encrypter and its recipient.
    pub const CGKA_NODE_SECRET_KEY: Self = Self::new("/keyhive/cgka/node-secret-key/v1/2026-10-31");

    /// The key an update seals its predecessors' root secrets under, from its
    /// own root secret.
    pub const CGKA_PREDECESSOR_SECRETS_KEY: Self =
        Self::new("/keyhive/cgka/predecessor-secrets-key/v1/2026-10-31");

    /// A block's application key, from its root secret, predecessors and
    /// content ref.
    pub const CONTENT_APPLICATION_KEY: Self =
        Self::new("/keyhive/content/application-key/v1/2026-10-31");

    /// A block's cipher key, from its application key.
    pub const CONTENT_ENCRYPTION_KEY: Self =
        Self::new("/keyhive/content/encryption-key/v1/2026-10-31");

    /// The digest of a block's document and header, in each chunk's associated
    /// data.
    pub const CONTENT_HEADER: Self = Self::new("/keyhive/content/header/v1/2026-10-31");

    /// A block's synthetic-nonce key, from its application key.
    pub const CONTENT_NONCE_KEY: Self = Self::new("/keyhive/content/nonce-key/v1/2026-10-31");

    /// The stream an individual's prekey for a document is drawn from.
    pub const PREKEY_SELECTION: Self = Self::new("/keyhive/prekey/selection/v1/2026-10-31");

    /// A sealed blob's cipher key, from the key it is sealed under.
    pub const SEAL_ENCRYPTION_KEY: Self = Self::new("/keyhive/seal/encryption-key/v1/2026-10-31");

    /// A sealed blob's synthetic-nonce key, from the key it is sealed under.
    pub const SEAL_NONCE_KEY: Self = Self::new("/keyhive/seal/nonce-key/v1/2026-10-31");

    /// Every context. [`Context::new`], the only way to make one, refuses a
    /// string that is not here, so the checks over this list (each well
    /// formed, no two the same) cover every context in use.
    const ALL: [&'static str; 10] = [
        "/keyhive/cgka/invitation-key/v1/2026-10-31",
        "/keyhive/cgka/node-secret-key/v1/2026-10-31",
        "/keyhive/cgka/predecessor-secrets-key/v1/2026-10-31",
        "/keyhive/content/application-key/v1/2026-10-31",
        "/keyhive/content/encryption-key/v1/2026-10-31",
        "/keyhive/content/header/v1/2026-10-31",
        "/keyhive/content/nonce-key/v1/2026-10-31",
        "/keyhive/prekey/selection/v1/2026-10-31",
        "/keyhive/seal/encryption-key/v1/2026-10-31",
        "/keyhive/seal/nonce-key/v1/2026-10-31",
    ];

    /// A context must be listed in [`Context::ALL`]: a constant that is not
    /// fails to compile.
    const fn new(context: &'static str) -> Self {
        assert!(listed(context), "a context must be listed in Context::ALL");
        Self(context)
    }

    /// The context string.
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Derive a 32-byte key from `key_material` under this context.
    #[allow(clippy::disallowed_methods)]
    pub fn derive_key(self, key_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(self.0, key_material)
    }

    /// A hasher in key-derivation mode under this context, for key material
    /// fed in parts or read as a stream.
    #[allow(clippy::disallowed_methods)]
    pub fn hasher(self) -> blake3::Hasher {
        blake3::Hasher::new_derive_key(self.0)
    }
}

const _: () = {
    let mut i = 0;
    while i < Context::ALL.len() {
        assert!(
            well_formed(Context::ALL[i].as_bytes()),
            "a context is /keyhive/<area>/<purpose>/v<N>/<YYYY-MM-DD>"
        );
        i += 1;
    }
    assert!(all_distinct(&Context::ALL), "two contexts are the same");
};

/// Whether `context` is one of [`Context::ALL`].
const fn listed(context: &str) -> bool {
    let mut i = 0;
    while i < Context::ALL.len() {
        if same(Context::ALL[i].as_bytes(), context.as_bytes()) {
            return true;
        }
        i += 1;
    }
    false
}

/// `/keyhive/<area>/<purpose>/v<N>/<YYYY-MM-DD>`, where the area and purpose
/// are lowercase ASCII letters, digits and inner hyphens, `N` has no leading
/// zero, and the date is a calendar day.
const fn well_formed(context: &[u8]) -> bool {
    const PREFIX: &[u8] = b"/keyhive/";
    let Some((prefix, rest)) = context.split_at_checked(PREFIX.len()) else {
        return false;
    };
    if !same(prefix, PREFIX) {
        return false;
    }
    let Some(rest) = name(rest) else {
        return false;
    };
    let Some(rest) = name(rest) else {
        return false;
    };
    let Some((b'v', rest)) = rest.split_first() else {
        return false;
    };
    let mut digits = 0;
    while digits < rest.len() && rest[digits].is_ascii_digit() {
        digits += 1;
    }
    if digits == 0 || rest[0] == b'0' || digits == rest.len() || rest[digits] != b'/' {
        return false;
    }
    let (_, date) = rest.split_at(digits + 1);
    is_date(date)
}

/// The rest after a non-empty `name/`, or `None`.
const fn name(bytes: &[u8]) -> Option<&[u8]> {
    let mut len = 0;
    while len < bytes.len() && bytes[len] != b'/' {
        let c = bytes[len];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return None;
        }
        len += 1;
    }
    if len == 0 || len == bytes.len() || bytes[0] == b'-' || bytes[len - 1] == b'-' {
        return None;
    }
    Some(bytes.split_at(len + 1).1)
}

/// Exactly `YYYY-MM-DD`, with a month from 1 to 12 and a day from 1 to 31.
const fn is_date(date: &[u8]) -> bool {
    let [y0, y1, y2, y3, b'-', m0, m1, b'-', d0, d1] = *date else {
        return false;
    };
    let digits = [y0, y1, y2, y3, m0, m1, d0, d1];
    let mut i = 0;
    while i < digits.len() {
        if !digits[i].is_ascii_digit() {
            return false;
        }
        i += 1;
    }
    let month = (m0 - b'0') * 10 + (m1 - b'0');
    let day = (d0 - b'0') * 10 + (d1 - b'0');
    1 <= month && month <= 12 && 1 <= day && day <= 31
}

const fn all_distinct(contexts: &[&str]) -> bool {
    let mut i = 0;
    while i < contexts.len() {
        let mut j = i + 1;
        while j < contexts.len() {
            if same(contexts[i].as_bytes(), contexts[j].as_bytes()) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_context_is_well_formed() {
        assert!(Context::ALL.iter().all(|c| well_formed(c.as_bytes())));
    }

    /// A well-formed context that is not in [`Context::ALL`] cannot be made.
    #[test]
    fn only_a_listed_context_can_be_made() {
        assert!(listed(Context::SEAL_NONCE_KEY.as_str()));
        assert!(!listed("/keyhive/seal/nonce-key/v2/2026-10-27"));
        assert!(!listed(""));
    }

    #[test]
    fn malformed_contexts_are_refused() {
        for context in [
            "",
            "/keyhive/",
            "/keyhive/content/nonce-key/v1/2026-10-31/",
            "/keyhive/content/nonce-key/2026-10-31",
            "/keyhive/content/nonce-key/v1",
            "/keyhive/content/v1/2026-10-31",
            "/keyhive/content/nonce-key/extra/v1/2026-10-31",
            "keyhive/content/nonce-key/v1/2026-10-31",
            "/keyhive2/content/nonce-key/v1/2026-10-31",
            "/keyhive/Content/nonce-key/v1/2026-10-31",
            "/keyhive/content/nonce_key/v1/2026-10-31",
            "/keyhive/content/nonce key/v1/2026-10-31",
            "/keyhive/-content/nonce-key/v1/2026-10-31",
            "/keyhive/content/nonce-key-/v1/2026-10-31",
            "/keyhive//nonce-key/v1/2026-10-31",
            "/keyhive/content/nonce-key/v/2026-10-31",
            "/keyhive/content/nonce-key/v0/2026-10-31",
            "/keyhive/content/nonce-key/v01/2026-10-31",
            "/keyhive/content/nonce-key/V1/2026-10-31",
            "/keyhive/content/nonce-key/v1a/2026-10-31",
            "/keyhive/content/nonce-key/v1/2026-13-01",
            "/keyhive/content/nonce-key/v1/2026-00-01",
            "/keyhive/content/nonce-key/v1/2026-10-00",
            "/keyhive/content/nonce-key/v1/2026-10-32",
            "/keyhive/content/nonce-key/v1/2026-1-26",
            "/keyhive/content/nonce-key/v1/2026/10/26",
            "/keyhive/content/nonce-key/v1/26-10-2026",
            "/keyhive/content/nonce-key/v1/2026-10-31x",
        ] {
            assert!(!well_formed(context.as_bytes()), "{context:?}");
        }
    }

    #[test]
    fn well_formed_contexts_are_accepted() {
        for context in [
            "/keyhive/a/b/v1/2000-01-01",
            "/keyhive/share-key/exchange-key/v10/2026-12-31",
            "/keyhive/area2/purpose3/v1/1999-09-09",
        ] {
            assert!(well_formed(context.as_bytes()), "{context:?}");
        }
    }

    #[test]
    fn a_repeated_context_is_caught() {
        let all = Context::ALL;
        assert!(all_distinct(&all));
        assert!(!all_distinct(&[all[0], all[1], all[0]]));
        assert!(!same(b"/keyhive/a", b"/keyhive/b"));
        assert!(!same(b"/keyhive/a", b"/keyhive/a/"));
    }
}
