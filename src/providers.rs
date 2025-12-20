use std::sync::Arc;

use crate::contracts::{AuthError, BoxFut, CurrentUserIdProvider};

pub struct FixedUserIdProvider<UserId>(pub Option<UserId>);

impl<UserId> FixedUserIdProvider<UserId> {
    pub fn new(id: Option<UserId>) -> Self {
        Self(id)
    }
}

impl<UserId> CurrentUserIdProvider<UserId> for FixedUserIdProvider<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<UserId>, AuthError>> {
        let id = self.0.clone();
        Box::pin(async move { Ok(id) })
    }
}

pub struct ChainUserIdProvider<UserId> {
    // English comment: Store only thread-safe providers, so the chain can be used in Send futures.
    providers: Vec<Arc<dyn CurrentUserIdProvider<UserId> + Send + Sync>>,
}

impl<UserId> ChainUserIdProvider<UserId> {
    pub fn new(providers: Vec<Arc<dyn CurrentUserIdProvider<UserId> + Send + Sync>>) -> Self {
        Self { providers }
    }
}

impl<UserId> CurrentUserIdProvider<UserId> for ChainUserIdProvider<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<UserId>, AuthError>> {
        let providers = self.providers.clone();

        Box::pin(async move {
            for p in providers {
                let id = p.current_user_id().await?;
                if id.is_some() {
                    return Ok(id);
                }
            }
            Ok(None)
        })
    }
}
