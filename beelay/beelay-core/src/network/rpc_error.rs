pub(crate) enum RpcError {
    // The other end said we are not authenticated
    AuthenticatedFailed,
    // The response we received failed authentication
    ResponseAuthFailed,
    // The other end said we are not authorized
    AuthorizationFailed,
    // The other end reported some kind of error
    ErrorReported(String),
    IncorrectResponseType,
    InvalidResponse,
    // There was no response (usually because the other end has gone away)
    NoResponse,
    StreamDisconnected,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::AuthenticatedFailed => write!(f, "Auth failed"),
            RpcError::ResponseAuthFailed => write!(f, "Response failed authentication"),
            RpcError::AuthorizationFailed => write!(f, "Authorization failed"),
            RpcError::NoResponse => write!(f, "we never got a response"),
            RpcError::StreamDisconnected => write!(f, "stream disconnected"),
            RpcError::ErrorReported(err) => write!(f, "{}", err),
            RpcError::IncorrectResponseType => write!(f, "Incorrect response type"),
            RpcError::InvalidResponse => write!(f, "invalid response"),
        }
    }
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for RpcError {}
