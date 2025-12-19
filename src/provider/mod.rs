use crate::{Authenticatable, AuthError};

pub mod chain;
pub mod fixed;

pub use chain::ChainProvider;
pub use fixed::FixedProvider;

pub trait AuthProvider<U: Authenticatable>: Send + Sync {
    fn user(&self) -> Result<Option<U>, AuthError>;
}
