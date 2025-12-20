use std::future::Future;
use std::pin::Pin;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub enum AuthError {
    Unauthenticated,
    Forbidden,
    InvalidCredentials,
    ExpiredSession,
    MissingSession,
    StorageFailure(String),
    ProviderFailure(String),
    Internal(String),
}

pub trait Principal: Send + Sync + 'static {
    type Id: Clone + Send + Sync + 'static;
    fn id(&self) -> Self::Id;
}

pub trait AuthContext: Send + Sync + 'static {
    type UserId: Clone + Send + Sync + 'static;
    type User: Principal<Id = Self::UserId> + Clone;

    fn current_user_id(&self) -> BoxFut<'_, Result<Option<Self::UserId>, AuthError>>;
    fn current_user(&self) -> BoxFut<'_, Result<Option<Self::User>, AuthError>>;

    fn require_user_id(&self) -> BoxFut<'_, Result<Self::UserId, AuthError>>;
    fn require_user(&self) -> BoxFut<'_, Result<Self::User, AuthError>>;
}

pub trait AuthSession: Send + Sync + 'static {
    type UserId: Clone + Send + Sync + 'static;

    fn sign_in(&self, user_id: &Self::UserId) -> BoxFut<'_, Result<(), AuthError>>;
    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>>;
}

pub trait CredentialsVerifier: Send + Sync + 'static {
    type Credentials: Send + Sync + 'static;
    type UserId: Clone + Send + Sync + 'static;

    fn verify(&self, credentials: &Self::Credentials) -> BoxFut<'_, Result<Self::UserId, AuthError>>;
}

pub trait Authorizer: Send + Sync + 'static {
    type User: Principal + Clone;

    fn has_role(&self, user: &Self::User, role: &str) -> BoxFut<'_, Result<bool, AuthError>>;
    fn has_permission(
        &self,
        user: &Self::User,
        permission: &str,
    ) -> BoxFut<'_, Result<bool, AuthError>>;
}

pub trait Policy: Send + Sync + 'static {
    type Ctx: AuthContext;
    fn check(&self, ctx: &Self::Ctx) -> BoxFut<'_, Result<(), AuthError>>;
}
