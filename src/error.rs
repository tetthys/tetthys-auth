#[derive(Debug, Clone)]
pub enum AuthError {
    Unauthenticated,
    Forbidden,
    MissingContext,
    MissingSession,
    ProviderFailed(String),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthenticated => write!(f, "unauthenticated"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::MissingContext => write!(f, "missing auth context"),
            Self::MissingSession => write!(f, "missing auth session"),
            Self::ProviderFailed(msg) => write!(f, "provider failed: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}
