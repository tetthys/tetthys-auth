use std::sync::{Arc, Mutex};

use crate::contracts::{
    AuthError, BoxFut, CurrentUserIdProvider, UserIdSession, UserLoader,
};

#[derive(Default)]
struct Cache<UserId, User> {
    // English comment: Cached user_id resolution result for this request scope.
    user_id: Option<Result<Option<UserId>, AuthError>>,
    // English comment: Cached user load result for this request scope.
    user: Option<Result<Option<User>, AuthError>>,
}

#[derive(Clone)]
pub struct AuthEngine<UserId, User> {
    user_id_provider: Arc<dyn CurrentUserIdProvider<UserId>>,
    user_loader: Option<Arc<dyn UserLoader<UserId, User>>>,
    session: Option<Arc<dyn UserIdSession<UserId>>>,
    cache: Arc<Mutex<Cache<UserId, User>>>,
}

impl<UserId, User> AuthEngine<UserId, User>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    pub fn new(
        user_id_provider: Arc<dyn CurrentUserIdProvider<UserId>>,
        user_loader: Option<Arc<dyn UserLoader<UserId, User>>>,
        session: Option<Arc<dyn UserIdSession<UserId>>>,
    ) -> Self {
        Self {
            user_id_provider,
            user_loader,
            session,
            cache: Arc::new(Mutex::new(Cache::default())),
        }
    }

    pub fn invalidate_cache(&self) {
        let mut g = self.cache.lock().expect("auth cache poisoned");
        g.user_id = None;
        g.user = None;
    }

    pub fn user_id(&self) -> BoxFut<'_, Result<Option<UserId>, AuthError>> {
        let provider = self.user_id_provider.clone();
        let cache = self.cache.clone();

        Box::pin(async move {
            {
                let g = cache
                    .lock()
                    .map_err(|_| AuthError::ProviderFailed("cache poisoned".into()))?;
                if let Some(v) = g.user_id.clone() {
                    return v;
                }
            }

            let res = provider.current_user_id().await;

            let mut g = cache
                .lock()
                .map_err(|_| AuthError::ProviderFailed("cache poisoned".into()))?;
            g.user_id = Some(res.clone());

            res
        })
    }

    pub fn check(&self) -> BoxFut<'_, Result<bool, AuthError>> {
        Box::pin(async move { Ok(self.user_id().await?.is_some()) })
    }

    pub fn require_user_id(&self) -> BoxFut<'_, Result<UserId, AuthError>> {
        Box::pin(async move { self.user_id().await?.ok_or(AuthError::Unauthenticated) })
    }

    pub fn user(&self) -> BoxFut<'_, Result<Option<User>, AuthError>> {
        let me = self.clone();

        Box::pin(async move {
            {
                let g = me
                    .cache
                    .lock()
                    .map_err(|_| AuthError::LoaderFailed("cache poisoned".into()))?;
                if let Some(v) = g.user.clone() {
                    return v;
                }
            }

            let Some(loader) = me.user_loader.clone() else {
                // English comment: No loader configured => cannot materialize user record.
                let res: Result<Option<User>, AuthError> = Ok(None);
                let mut g = me
                    .cache
                    .lock()
                    .map_err(|_| AuthError::LoaderFailed("cache poisoned".into()))?;
                g.user = Some(res.clone());
                return res;
            };

            let Some(uid) = me.user_id().await? else {
                let res: Result<Option<User>, AuthError> = Ok(None);
                let mut g = me
                    .cache
                    .lock()
                    .map_err(|_| AuthError::LoaderFailed("cache poisoned".into()))?;
                g.user = Some(res.clone());
                return res;
            };

            let res = loader.load_user(&uid).await;

            let mut g = me
                .cache
                .lock()
                .map_err(|_| AuthError::LoaderFailed("cache poisoned".into()))?;
            g.user = Some(res.clone());

            res
        })
    }

    pub fn require(&self) -> BoxFut<'_, Result<User, AuthError>> {
        Box::pin(async move { self.user().await?.ok_or(AuthError::Unauthenticated) })
    }

    pub fn sign_in_by_user_id(&self, user_id: &UserId) -> BoxFut<'_, Result<(), AuthError>> {
        let session = self.session.clone();
        let me = self.clone();
        let uid = user_id.clone();

        Box::pin(async move {
            let sess = session.ok_or(AuthError::MissingSession)?;
            sess.sign_in_by_user_id(&uid).await?;
            me.invalidate_cache();
            Ok(())
        })
    }

    pub fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>> {
        let session = self.session.clone();
        let me = self.clone();

        Box::pin(async move {
            let sess = session.ok_or(AuthError::MissingSession)?;
            sess.sign_out().await?;
            me.invalidate_cache();
            Ok(())
        })
    }
}
