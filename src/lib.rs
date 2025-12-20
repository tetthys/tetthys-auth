pub mod adapters;
pub mod contracts;
pub mod engine;
pub mod facade;
pub mod providers;
pub mod scope;

pub use contracts::{
    AuthError, BoxFut, CurrentUserIdProvider, UserIdSession, UserLoader,
};
pub use engine::AuthEngine;
pub use facade::{
    auth_check, auth_id, auth_require, auth_require_id, auth_sign_in_by_user_id, auth_sign_out,
    auth_user,
};
pub use providers::{ChainUserIdProvider, FixedUserIdProvider};
