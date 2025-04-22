pub(crate) enum RpcError {
    // The other end said we are not authenticated
    AuthenticatedFailed,
    // The other end said we are not authorized
    AuthorizationFailed,
    // The other end reported some kind of error
    ErrorReported(String),
    IncorrectResponseType,
    // There was no response (usually because the other end has gone away)
    NoResponse,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::AuthenticatedFailed => write!(f, "Auth failed"),
            RpcError::AuthorizationFailed => write!(f, "Authorization failed"),
            RpcError::NoResponse => write!(f, "we never got a response"),
            RpcError::ErrorReported(err) => write!(f, "{}", err),
            RpcError::IncorrectResponseType => write!(f, "Incorrect response type"),
        }
    }
}

impl std::fmt::Debug for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for RpcError {}
