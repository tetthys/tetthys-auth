use crate::{Authenticatable, AuthError};
use super::AuthProvider;

pub struct ChainProvider<U: Authenticatable> {
    providers: Vec<Box<dyn AuthProvider<U>>>,
}

impl<U: Authenticatable> ChainProvider<U> {
    pub fn new(providers: Vec<Box<dyn AuthProvider<U>>>) -> Self {
        Self { providers }
    }
}

impl<U: Authenticatable> AuthProvider<U> for ChainProvider<U> {
    fn user(&self) -> Result<Option<U>, AuthError> {
        for p in &self.providers {
            match p.user()? {
                Some(u) => return Ok(Some(u)),
                None => continue,
            }
        }
        Ok(None)
    }
}
