use crate::{Authenticatable, AuthContext};

pub trait AuthContextAccessor<U: Authenticatable> {
    fn get() -> Option<&'static AuthContext<U>>;
}
