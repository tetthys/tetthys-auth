use crate::{Authenticatable, AuthError};
use super::AuthProvider;

pub struct FixedProvider<U: Authenticatable>(pub Option<U>);

impl<U: Authenticatable> AuthProvider<U> for FixedProvider<U> {
    fn user(&self) -> Result<Option<U>, AuthError> {
        Ok(self.0.clone())
    }
}
