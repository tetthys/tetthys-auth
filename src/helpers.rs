use crate::{Authenticatable, Authorizable, AuthError};
use crate::accessor::AuthContextAccessor;
use crate::session::AuthSessionAccessor;

// ---------------- Auth (Laravel-like) ----------------

pub fn auth_user<U: Authenticatable>() -> Result<Option<U>, AuthError>
where
    (): AuthContextAccessor<U>,
{
    let ctx = <() as AuthContextAccessor<U>>::get().ok_or(AuthError::MissingContext)?;
    ctx.user()
}

pub fn auth_check<U: Authenticatable>() -> Result<bool, AuthError>
where
    (): AuthContextAccessor<U>,
{
    Ok(auth_user::<U>()?.is_some())
}

pub fn auth_require<U: Authenticatable>() -> Result<U, AuthError>
where
    (): AuthContextAccessor<U>,
{
    auth_user::<U>()?.ok_or(AuthError::Unauthenticated)
}

pub fn auth_id<U: Authenticatable>() -> Result<Option<U::Id>, AuthError>
where
    (): AuthContextAccessor<U>,
{
    Ok(auth_user::<U>()?.map(|u| u.id()))
}

pub fn auth_require_id<U: Authenticatable>() -> Result<U::Id, AuthError>
where
    (): AuthContextAccessor<U>,
{
    Ok(auth_require::<U>()?.id())
}

pub fn auth_assert<U: Authenticatable>() -> Result<(), AuthError>
where
    (): AuthContextAccessor<U>,
{
    auth_require::<U>().map(|_| ())
}

pub fn auth_if<U, F, R>(f: F) -> Result<Option<R>, AuthError>
where
    U: Authenticatable,
    (): AuthContextAccessor<U>,
    F: FnOnce(U) -> R,
{
    Ok(auth_user::<U>()?.map(f))
}

// ---------------- Authorization ----------------

pub fn auth_can<U>(ability: &str) -> Result<bool, AuthError>
where
    U: Authenticatable + Authorizable,
    (): AuthContextAccessor<U>,
{
    Ok(auth_user::<U>()?.is_some_and(|u| u.can(ability)))
}

pub fn auth_can_any<U>(abilities: &[&str]) -> Result<bool, AuthError>
where
    U: Authenticatable + Authorizable,
    (): AuthContextAccessor<U>,
{
    let Some(u) = auth_user::<U>()? else { return Ok(false); };
    Ok(abilities.iter().any(|a| u.can(a)))
}

pub fn auth_has_role<U>(role: &str) -> Result<bool, AuthError>
where
    U: Authenticatable + Authorizable,
    (): AuthContextAccessor<U>,
{
    Ok(auth_user::<U>()?.is_some_and(|u| u.has_role(role)))
}

pub fn auth_has_any_role<U>(roles: &[&str]) -> Result<bool, AuthError>
where
    U: Authenticatable + Authorizable,
    (): AuthContextAccessor<U>,
{
    let Some(u) = auth_user::<U>()? else { return Ok(false); };
    Ok(roles.iter().any(|r| u.has_role(r)))
}

// ---------------- Session (sign in/out) ----------------

pub fn auth_sign_in<U: Authenticatable>(user: &U) -> Result<(), AuthError>
where
    (): AuthSessionAccessor<U> + AuthContextAccessor<U>,
{
    let sess = <() as AuthSessionAccessor<U>>::get().ok_or(AuthError::MissingSession)?;
    sess.sign_in(user)?;

    if let Some(ctx) = <() as AuthContextAccessor<U>>::get() {
        ctx.invalidate()?;
    }
    Ok(())
}

pub fn auth_sign_out<U: Authenticatable>() -> Result<(), AuthError>
where
    (): AuthSessionAccessor<U> + AuthContextAccessor<U>,
{
    let sess = <() as AuthSessionAccessor<U>>::get().ok_or(AuthError::MissingSession)?;
    sess.sign_out()?;

    if let Some(ctx) = <() as AuthContextAccessor<U>>::get() {
        ctx.invalidate()?;
    }
    Ok(())
}
