pub mod accessor;
pub mod authenticatable;
pub mod authorizable;
pub mod context;
pub mod error;
pub mod helpers;
pub mod provider;
pub mod session;

pub use accessor::AuthContextAccessor;
pub use authenticatable::Authenticatable;
pub use authorizable::{Ability, Authorization, Authorizable};
pub use context::AuthContext;
pub use error::AuthError;
pub use provider::{AuthProvider, ChainProvider, FixedProvider};
pub use session::{AuthSession, AuthSessionAccessor};

pub use helpers::{
    // auth
    auth_check,
    auth_user,
    auth_require,
    auth_id,
    auth_require_id,
    auth_assert,
    auth_if,
    // authorization
    auth_can,
    auth_can_any,
    auth_has_role,
    auth_has_any_role,
    // session
    auth_sign_in,
    auth_sign_out,
};
