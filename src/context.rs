use std::sync::Mutex;

use crate::{Authenticatable, AuthError};
use crate::provider::AuthProvider;

pub struct AuthContext<U: Authenticatable> {
    provider: Box<dyn AuthProvider<U>>,
    cache: Mutex<Option<Result<Option<U>, AuthError>>>,
}

impl<U: Authenticatable> AuthContext<U> {
    pub fn new(provider: Box<dyn AuthProvider<U>>) -> Self {
        Self {
            provider,
            cache: Mutex::new(None),
        }
    }

    pub fn user(&self) -> Result<Option<U>, AuthError> {
        let mut g = self
            .cache
            .lock()
            .map_err(|_| AuthError::ProviderFailed("cache poisoned".into()))?;

        if let Some(v) = g.clone() {
            return v;
        }

        let v = self.provider.user();
        *g = Some(v.clone());
        v
    }

    pub fn check(&self) -> Result<bool, AuthError> {
        Ok(self.user()?.is_some())
    }

    pub fn require(&self) -> Result<U, AuthError> {
        self.user()?.ok_or(AuthError::Unauthenticated)
    }

    pub fn invalidate(&self) -> Result<(), AuthError> {
        let mut g = self
            .cache
            .lock()
            .map_err(|_| AuthError::ProviderFailed("cache poisoned".into()))?;
        *g = None;
        Ok(())
    }
}
