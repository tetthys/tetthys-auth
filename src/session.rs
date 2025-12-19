use crate::{Authenticatable, AuthError};

pub trait AuthSession<U: Authenticatable>: Send + Sync {
    fn sign_in(&self, user: &U) -> Result<(), AuthError>;
    fn sign_out(&self) -> Result<(), AuthError>;
}

pub trait AuthSessionAccessor<U: Authenticatable> {
    fn get() -> Option<&'static dyn AuthSession<U>>;
}
