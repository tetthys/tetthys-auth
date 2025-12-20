#![cfg(feature = "axum-ssr")]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRef, Request, State};
use axum::response::IntoResponse;
use leptos::prelude::*;
use leptos::prelude::LeptosOptions;
use leptos_axum::{handle_server_fns_with_context, render_app_to_stream_with_context};

use crate::contracts::{
    AuthError, BoxFut, CurrentUserIdProvider, UserIdSession, UserLoader,
};
use crate::engine::AuthEngine;

/// Extract user_id from request (cookie/header/jwt/etc).
pub trait RequestUserIdResolver<UserId>: Send + Sync + 'static {
    fn resolve_user_id(&self, req: &Request<Body>) -> Result<Option<UserId>, AuthError>;
}

/// Load user record by user_id from storage (e.g. DB users table).
pub trait RepoUserLoader<UserId, User>: Send + Sync + 'static {
    fn find_by_user_id(&self, user_id: &UserId) -> BoxFut<'_, Result<Option<User>, AuthError>>;
}

/// Mutate session by user_id (set/clear cookie, DB session table, etc).
pub trait RequestUserIdSessionMutator<UserId>: Send + Sync + 'static {
    fn sign_in_by_user_id(
        &self,
        req: &Request<Body>,
        user_id: &UserId,
    ) -> BoxFut<'_, Result<(), AuthError>>;

    fn sign_out(&self, req: &Request<Body>) -> BoxFut<'_, Result<(), AuthError>>;
}

pub struct RequestScopedUserIdProvider<UserId> {
    req: Request<Body>,
    resolver: Arc<dyn RequestUserIdResolver<UserId>>,
}

impl<UserId> RequestScopedUserIdProvider<UserId> {
    pub fn new(req: Request<Body>, resolver: Arc<dyn RequestUserIdResolver<UserId>>) -> Self {
        Self { req, resolver }
    }
}

impl<UserId> CurrentUserIdProvider<UserId> for RequestScopedUserIdProvider<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<UserId>, AuthError>> {
        let res = self.resolver.resolve_user_id(&self.req);
        Box::pin(async move { res })
    }
}

pub struct RequestScopedUserLoader<UserId, User> {
    repo: Arc<dyn RepoUserLoader<UserId, User>>,
}

impl<UserId, User> RequestScopedUserLoader<UserId, User> {
    pub fn new(repo: Arc<dyn RepoUserLoader<UserId, User>>) -> Self {
        Self { repo }
    }
}

impl<UserId, User> UserLoader<UserId, User> for RequestScopedUserLoader<UserId, User>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    fn load_user(&self, user_id: &UserId) -> BoxFut<'_, Result<Option<User>, AuthError>> {
        self.repo.find_by_user_id(user_id)
    }
}

pub struct RequestScopedUserIdSession<UserId> {
    req: Request<Body>,
    mutator: Arc<dyn RequestUserIdSessionMutator<UserId>>,
}

impl<UserId> RequestScopedUserIdSession<UserId> {
    pub fn new(req: Request<Body>, mutator: Arc<dyn RequestUserIdSessionMutator<UserId>>) -> Self {
        Self { req, mutator }
    }
}

impl<UserId> UserIdSession<UserId> for RequestScopedUserIdSession<UserId>
where
    UserId: Clone + Send + Sync + 'static,
{
    fn sign_in_by_user_id(&self, user_id: &UserId) -> BoxFut<'_, Result<(), AuthError>> {
        self.mutator.sign_in_by_user_id(&self.req, user_id)
    }

    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>> {
        self.mutator.sign_out(&self.req)
    }
}

#[derive(Clone)]
pub struct AuthAdapterState<UserId, User> {
    pub resolver: Arc<dyn RequestUserIdResolver<UserId>>,
    pub repo: Arc<dyn RepoUserLoader<UserId, User>>,
    pub session_mutator: Option<Arc<dyn RequestUserIdSessionMutator<UserId>>>,
}

impl<UserId, User> AuthAdapterState<UserId, User> {
    pub fn new(
        resolver: Arc<dyn RequestUserIdResolver<UserId>>,
        repo: Arc<dyn RepoUserLoader<UserId, User>>,
        session_mutator: Option<Arc<dyn RequestUserIdSessionMutator<UserId>>>,
    ) -> Self {
        Self {
            resolver,
            repo,
            session_mutator,
        }
    }
}

pub async fn leptos_server_fns_handler_with_auth<UserId, User, S>(
    State(app_state): State<S>,
    req: Request<Body>,
) -> impl IntoResponse
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
    AuthAdapterState<UserId, User>: FromRef<S>,
{
    let auth = AuthAdapterState::<UserId, User>::from_ref(&app_state);

    handle_server_fns_with_context(req, move |req| {
        let user_id_provider = Arc::new(RequestScopedUserIdProvider::new(
            req.clone(),
            auth.resolver.clone(),
        ));

        let user_loader = Arc::new(RequestScopedUserLoader::new(auth.repo.clone()))
            as Arc<dyn UserLoader<UserId, User>>;

        let session = auth.session_mutator.as_ref().map(|m| {
            Arc::new(RequestScopedUserIdSession::new(req.clone(), m.clone()))
                as Arc<dyn UserIdSession<UserId>>
        });

        let engine = AuthEngine::new(user_id_provider, Some(user_loader), session);
        provide_context(Arc::new(engine));
    })
    .await
}

pub fn leptos_ssr_render_handler_with_auth<UserId, User, S, IV>(
    app_state: S,
    leptos_options: LeptosOptions,
    app_fn: impl Fn() -> IV + Clone + Send + 'static,
) -> impl axum::handler::Handler<(), S>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
    S: Clone + Send + Sync + 'static,
    AuthAdapterState<UserId, User>: FromRef<S>,
    IV: IntoView + 'static,
{
    render_app_to_stream_with_context(
        leptos_options,
        move |req| {
            let auth = AuthAdapterState::<UserId, User>::from_ref(&app_state);

            let user_id_provider = Arc::new(RequestScopedUserIdProvider::new(
                req.clone(),
                auth.resolver.clone(),
            ));

            let user_loader = Arc::new(RequestScopedUserLoader::new(auth.repo.clone()))
                as Arc<dyn UserLoader<UserId, User>>;

            let session = auth.session_mutator.as_ref().map(|m| {
                Arc::new(RequestScopedUserIdSession::new(req.clone(), m.clone()))
                    as Arc<dyn UserIdSession<UserId>>
            });

            let engine = AuthEngine::new(user_id_provider, Some(user_loader), session);
            provide_context(Arc::new(engine));
        },
        app_fn,
    )
}
