use std::future::Future;
use std::pin::Pin;

#[derive(Debug, Clone)]
pub enum AuthError {
    MissingContext,
    ProviderFailed(String),
    LoaderFailed(String),
    SessionFailed(String),
    Unauthenticated,
    MissingSession,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolve the current authenticated user id for this request.
/// - None => unauthenticated
/// - Some(user_id) => authenticated principal id
pub trait CurrentUserIdProvider<UserId>: Send + Sync + 'static {
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<UserId>, AuthError>>;
}

/// Load user record by user_id (e.g. from users table).
/// - Return None if not found (stale session, deleted user, etc).
pub trait UserLoader<UserId, User>: Send + Sync + 'static {
    fn load_user(&self, user_id: &UserId) -> BoxFut<'_, Result<Option<User>, AuthError>>;
}

/// Session mutator that stores only the user_id.
pub trait UserIdSession<UserId>: Send + Sync + 'static {
    fn sign_in_by_user_id(&self, user_id: &UserId) -> BoxFut<'_, Result<(), AuthError>>;
    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>>;
}
