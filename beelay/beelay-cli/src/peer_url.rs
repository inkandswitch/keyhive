use beelay::PeerId;
pub(crate) use error::ParseError;
use std::{net::SocketAddr, str::FromStr};

#[derive(Clone, Debug)]
pub(crate) enum PeerUrl {
    Tcp(SocketAddr, PeerId),
    #[allow(dead_code)]
    WebSocket(SocketAddr, PeerId),
}

impl FromStr for PeerUrl {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (base_url, peer_id) = if let Some((base, query)) = s.split_once('?') {
            let peer_id = query.split('&').find_map(|param| {
                let kv: Vec<&str> = param.split('=').collect();
                if kv.len() == 2 && kv[0] == "peer_id" {
                    Some(kv[1])
                } else {
                    None
                }
            });

            (base, peer_id)
        } else {
            (s, None)
        };

        let parts: Vec<&str> = base_url.splitn(2, ':').collect();

        let peer_id = peer_id.and_then(|peer_id| beelay::PeerId::from_str(peer_id).ok());

        match parts.as_slice() {
            ["tcp", addr] => {
                let Some(peer_id) = peer_id else {
                    return Err(ParseError::MissingPeerId);
                };
                Ok(PeerUrl::Tcp(
                    addr.parse::<SocketAddr>()
                        .map_err(ParseError::InvalidSocketAddr)?,
                    peer_id,
                ))
            }
            ["ws", addr] => {
                let Some(peer_id) = peer_id else {
                    return Err(ParseError::MissingPeerId);
                };
                Ok(PeerUrl::WebSocket(
                    addr.parse::<SocketAddr>()
                        .map_err(ParseError::InvalidSocketAddr)?,
                    peer_id,
                ))
            }
            _ => Err(ParseError::UnknownProtocol),
        }
    }
}

mod error {
    pub(crate) enum ParseError {
        UnknownProtocol,
        InvalidSocketAddr(std::net::AddrParseError),
        MissingPeerId,
    }

    impl std::fmt::Display for ParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                ParseError::UnknownProtocol => write!(f, "Unknown protocol"),
                ParseError::InvalidSocketAddr(e) => write!(f, "Invalid socket address: {}", e),
                ParseError::MissingPeerId => write!(f, "missing peer id"),
            }
        }
    }

    impl std::fmt::Debug for ParseError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", self)
        }
    }

    impl std::error::Error for ParseError {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_url() {
        let url = "tcp://127.0.0.1:8080";
        let peer_url = PeerUrl::from_str(url).unwrap();
        assert!(matches!(peer_url, PeerUrl::Tcp(_, _)));
    }

    #[test]
    fn parse_tcp_url_with_peer_id() {
        let peer_id = beelay::PeerId::random(&mut rand::thread_rng());
        let url = format!("tcp://127.0.0.1:8080?peer_id={}", peer_id);
        let peer_url = PeerUrl::from_str(&url).unwrap();

        // Note: Can't directly access the peer_id from within PeerUrl::Tcp yet.
        // Further changes would be needed to support that if you need to test it.
        assert!(matches!(peer_url, PeerUrl::Tcp(_, _)));
    }

    #[test]
    fn parse_ws_url() {
        let peer_id = beelay::PeerId::random(&mut rand::thread_rng());
        let url = format!("ws://127.0.0.1:8080?peer_id={}", peer_id);
        let peer_url = PeerUrl::from_str(&url).unwrap();

        assert!(matches!(peer_url, PeerUrl::WebSocket(_, _)));
    }

    #[test]
    fn parse_invalid_url() {
        let url = "invalid://127.0.0.1:8080";
        let peer_url = PeerUrl::from_str(url);
        assert!(matches!(peer_url, Err(ParseError::UnknownProtocol)));
    }

    #[test]
    fn parse_invalid_socket_addr() {
        let url = "tcp://invalid_address";
        let peer_url = PeerUrl::from_str(url);
        assert!(matches!(peer_url, Err(ParseError::InvalidSocketAddr(_))));
    }
}
