use crate::access::Access;
use crate::crypto::{encrypted::Encrypted, hash::Hash, share_key::ShareKey, signed::Signed};
use crate::principal::agent::Agent;
use crate::principal::group::Group;
use crate::principal::membered::Membered;
use crate::principal::stateless::Stateless;
use crate::principal::traits::Verifiable;
use chacha20poly1305::AeadInPlace;
use std::collections::{BTreeMap, BTreeSet};

// FIXME rneame membership
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct Group<'a> {
//     pub id: Stateless,
//     pub direct_members: BTreeMap<&'a Agent, Access>,
// }
//
// impl PartialOrd for Group<'_> {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         match self.id.as_bytes().partial_cmp(&other.id.as_bytes()) {
//             Some(Ordering::Equal) => self.direct_members.partial_cmp(&other.direct_members),
//             otherwise => otherwise,
//         }
//     }
// }
//
// impl Ord for Group<'_> {
//     fn cmp(&self, other: &Self) -> Ordering {
//         match self.id.as_bytes().cmp(&other.id.as_bytes()) {
//             Ordering::Equal => self.direct_members.cmp(&other.direct_members),
//             otherwise => otherwise,
//         }
//     }
// }

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GroupStore {
    pub groups: BTreeMap<Stateless, Membered>,
}

impl GroupStore {
    pub fn new() -> Self {
        GroupStore {
            groups: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, membered: Membered) {
        self.groups
            .insert(membered.verifying_key().clone().into(), membered);
    }

    pub fn get(&self, id: &Stateless) -> Option<&Membered> {
        self.groups.get(id)
    }

    // FIXME shoudl be more like this:
    // pub fn transative_members(&self, group: &Group) -> BTreeMap<&Agent, Access> {
    pub fn transative_members(&self, group: &Group) -> BTreeMap<Agent, Access> {
        struct GroupAccess {
            agent: Agent,
            agent_access: Access,
            parent_access: Access,
        }

        let mut explore: Vec<GroupAccess> = vec![];

        for (k, v) in group.delegates.iter() {
            explore.push(GroupAccess {
                agent: k.clone(),
                agent_access: *v,
                parent_access: Access::Admin,
            });
        }

        let mut caps: BTreeMap<Agent, Access> = BTreeMap::new();

        while !explore.is_empty() {
            if let Some(GroupAccess {
                agent: member,
                agent_access: access,
                parent_access,
            }) = explore.pop()
            {
                match member {
                    Agent::Stateless(_) => {
                        let current_path_access = access.min(parent_access);

                        let best_access = if let Some(prev_found_path_access) = caps.get(&member) {
                            (*prev_found_path_access).max(current_path_access)
                        } else {
                            current_path_access
                        };

                        caps.insert(member, best_access);
                    }
                    _ => {
                        if let Some(group) = self.groups.get(&member.verifying_key().into()) {
                            for (mem, pow) in group.members() {
                                let current_path_access = access.min(pow).min(parent_access);

                                let best_access =
                                    if let Some(prev_found_path_access) = caps.get(&mem) {
                                        (*prev_found_path_access).max(current_path_access)
                                    } else {
                                        current_path_access
                                    };

                                explore.push(GroupAccess {
                                    agent: mem,
                                    agent_access: best_access,
                                    parent_access,
                                });
                            }
                        }
                    }
                }
            }
        }

        caps
    }
}

////////////////

// FIXME Placeholder
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaChaKey {
    bytes: [u8; 32],
}

pub fn dcgka_2m_broadcast(
    key: &XChaChaKey,
    sharer_key: &x25519_dalek::StaticSecret,
    public_keys: BTreeSet<&ShareKey>,
) -> BTreeMap<ShareKey, Encrypted<chacha20poly1305::XChaCha20Poly1305>> {
    let mut wrapped_key_map = BTreeMap::new();

    for pk in public_keys {
        let shared_secret: x25519_dalek::SharedSecret = sharer_key.diffie_hellman(&pk.0);
        // FIXME convert shared secret to bytes
        // encrypt payload

        // let generic_arr:  = generic_array::GenericArray::from_slice(shared_secret.as_bytes());

        let chacha_key: chacha20poly1305::XChaCha20Poly1305 =
            // FIXME prefer fixed size key with ::new(key: Key)
            chacha20poly1305::KeyInit::new_from_slice(shared_secret.as_bytes())
                .expect("FIXME");

        let nonce = chacha20poly1305::XNonce::from_slice(&[0u8; 24]);

        let mut key_clone = key.clone();

        let mut bytes = chacha_key
            .encrypt_in_place_detached(nonce, &[], &mut key_clone.bytes)
            .expect("FIXME")
            .to_vec();

        bytes.append(&mut key.bytes.to_vec());

        let wrapped_key: Encrypted<chacha20poly1305::XChaCha20Poly1305> = Encrypted {
            nonce: nonce.as_slice().try_into().expect("FIXME"),
            ciphertext: bytes,
            _phantom: std::marker::PhantomData,
        };

        wrapped_key_map.insert(*pk, wrapped_key);
    }

    wrapped_key_map
}

pub struct SetReadKeyOp {
    pub set_read_key: x25519_dalek::StaticSecret,
    pub parents: BTreeSet<Hash<Signed<SetReadKeyOp>>>,
}

// pub struct MyPubKey {
//     pub read_key_ops: Signed<MyReadKeyOps>,
// }

pub struct MyReadKeyOps {
    // FIXME use a single signture?
    pub cold_call_ops: BTreeSet<SetReadKeyOp>,
    pub for_group_ops: BTreeMap<ed25519_dalek::VerifyingKey, BTreeSet<SetReadKeyOp>>,
}

pub struct MyReadKeyState {
    pub cold_call: x25519_dalek::StaticSecret,
    pub for_group: BTreeMap<ed25519_dalek::VerifyingKey, x25519_dalek::StaticSecret>,
}

pub struct Art {
    pub members: BTreeSet<ed25519_dalek::VerifyingKey>,
    pub materialized_tree: ArtNode,
}

pub struct ArtNode {
    pub pk: x25519_dalek::PublicKey,

    pub left: Option<Box<ArtNode>>,
    pub right: Option<Box<ArtNode>>,
}

impl ArtNode {
    pub fn replace(
        &mut self,
        stale: &x25519_dalek::PublicKey,
        fresh_pk: &x25519_dalek::PublicKey,
        fresh_sk: &x25519_dalek::StaticSecret,
    ) -> () {
        if self.pk == *stale {
            self.pk = *fresh_pk;
        }

        if let Some(left) = &mut self.left {
            left.replace(stale, fresh_pk, fresh_sk);
        }

        if let Some(right) = &mut self.right {
            right.replace(stale, fresh_pk, fresh_sk);
        }
    }
}
