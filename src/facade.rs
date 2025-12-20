use crate::contracts::AuthError;
use crate::scope::get_engine;

pub async fn auth_id<UserId, User>() -> Result<Option<UserId>, AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.user_id().await
}

pub async fn auth_check<UserId, User>() -> Result<bool, AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.check().await
}

pub async fn auth_user<UserId, User>() -> Result<Option<User>, AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.user().await
}

pub async fn auth_require_id<UserId, User>() -> Result<UserId, AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.require_user_id().await
}

pub async fn auth_require<UserId, User>() -> Result<User, AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.require().await
}

pub async fn auth_sign_in_by_user_id<UserId, User>(user_id: &UserId) -> Result<(), AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.sign_in_by_user_id(user_id).await
}

pub async fn auth_sign_out<UserId, User>() -> Result<(), AuthError>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    let eng = get_engine::<UserId, User>().ok_or(AuthError::MissingContext)?;
    eng.sign_out().await
}
