use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use futures::executor::block_on;

use tetthys_auth::{
    auth_check, auth_id, auth_require, auth_require_id, auth_sign_in_by_user_id, auth_sign_out,
    auth_user, AuthEngine, AuthError, BoxFut, ChainUserIdProvider, CurrentUserIdProvider,
    FixedUserIdProvider, UserIdSession, UserLoader,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestUser {
    id: i64,
}

// ------------------------------
// Test providers/loaders/sessions
// ------------------------------

struct CountingUserIdProvider {
    calls: Arc<AtomicUsize>,
    id: Option<i64>,
    fail: bool,
}

impl CountingUserIdProvider {
    fn new(calls: Arc<AtomicUsize>, id: Option<i64>) -> Self {
        Self { calls, id, fail: false }
    }

    fn failing(calls: Arc<AtomicUsize>) -> Self {
        Self { calls, id: None, fail: true }
    }
}

impl CurrentUserIdProvider<i64> for CountingUserIdProvider {
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<i64>, AuthError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let id = self.id;
        let fail = self.fail;

        Box::pin(async move {
            if fail {
                return Err(AuthError::ProviderFailed("boom".into()));
            }
            Ok(id)
        })
    }
}

struct CountingUserLoader {
    calls: Arc<AtomicUsize>,
    missing: bool,
}

impl CountingUserLoader {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls, missing: false }
    }

    fn missing(calls: Arc<AtomicUsize>) -> Self {
        Self { calls, missing: true }
    }
}

impl UserLoader<i64, TestUser> for CountingUserLoader {
    fn load_user(&self, user_id: &i64) -> BoxFut<'_, Result<Option<TestUser>, AuthError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let id = *user_id;
        let missing = self.missing;

        Box::pin(async move {
            if missing {
                return Ok(None);
            }
            Ok(Some(TestUser { id }))
        })
    }
}

#[derive(Clone)]
struct SharedIdStore {
    id: Arc<Mutex<Option<i64>>>,
}

impl SharedIdStore {
    fn new(initial: Option<i64>) -> Self {
        Self { id: Arc::new(Mutex::new(initial)) }
    }
}

struct StoreUserIdProvider {
    store: SharedIdStore,
}

impl CurrentUserIdProvider<i64> for StoreUserIdProvider {
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<i64>, AuthError>> {
        let store = self.store.clone();
        Box::pin(async move {
            let g = store
                .id
                .lock()
                .map_err(|_| AuthError::ProviderFailed("store poisoned".into()))?;
            Ok(*g)
        })
    }
}

struct StoreUserIdSession {
    store: SharedIdStore,
}

impl UserIdSession<i64> for StoreUserIdSession {
    fn sign_in_by_user_id(&self, user_id: &i64) -> BoxFut<'_, Result<(), AuthError>> {
        let store = self.store.clone();
        let id = *user_id;

        Box::pin(async move {
            let mut g = store
                .id
                .lock()
                .map_err(|_| AuthError::SessionFailed("store poisoned".into()))?;
            *g = Some(id);
            Ok(())
        })
    }

    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>> {
        let store = self.store.clone();
        Box::pin(async move {
            let mut g = store
                .id
                .lock()
                .map_err(|_| AuthError::SessionFailed("store poisoned".into()))?;
            *g = None;
            Ok(())
        })
    }
}

// ------------------------------
// Tests
// ------------------------------

#[test]
fn pipeline_unauthenticated_basics() {
    // No scope => MissingContext
    let e = block_on(auth_user::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::MissingContext));

    // Engine with fixed None
    let idp = Arc::new(FixedUserIdProvider::<i64>(None));
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;
    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));

    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), false);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), None);
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), None);

    let e = block_on(auth_require_id::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));

    let e = block_on(auth_require::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));
}

#[test]
fn pipeline_authenticated_id_and_user() {
    let idp = Arc::new(FixedUserIdProvider::<i64>(Some(7)));
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;
    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), true);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), Some(7));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), Some(TestUser { id: 7 }));
    assert_eq!(block_on(auth_require_id::<i64, TestUser>()).unwrap(), 7);
    assert_eq!(block_on(auth_require::<i64, TestUser>()).unwrap(), TestUser { id: 7 });
}

#[test]
fn user_id_chain_provider_order_and_fallback() {
    let calls_a = Arc::new(AtomicUsize::new(0));
    let calls_b = Arc::new(AtomicUsize::new(0));

    let p1 = Arc::new(CountingUserIdProvider::new(calls_a.clone(), None))
        as Arc<dyn CurrentUserIdProvider<i64>>;
    let p2 = Arc::new(CountingUserIdProvider::new(calls_b.clone(), Some(9)))
        as Arc<dyn CurrentUserIdProvider<i64>>;

    let chain = Arc::new(ChainUserIdProvider::new(vec![p1, p2]));
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;

    let engine = Arc::new(AuthEngine::new(chain, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), Some(9));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), Some(TestUser { id: 9 }));

    assert_eq!(calls_a.load(Ordering::SeqCst), 1);
    assert_eq!(calls_b.load(Ordering::SeqCst), 1);
}

#[test]
fn engine_caches_user_id_and_user_per_request_scope() {
    let id_calls = Arc::new(AtomicUsize::new(0));
    let user_calls = Arc::new(AtomicUsize::new(0));

    let idp = Arc::new(CountingUserIdProvider::new(id_calls.clone(), Some(3)));
    let loader = Arc::new(CountingUserLoader::new(user_calls.clone()))
        as Arc<dyn UserLoader<i64, TestUser>>;

    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), true);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), Some(3));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), Some(TestUser { id: 3 }));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), Some(TestUser { id: 3 }));

    assert_eq!(id_calls.load(Ordering::SeqCst), 1);
    assert_eq!(user_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_errors_propagate() {
    let calls = Arc::new(AtomicUsize::new(0));
    let idp = Arc::new(CountingUserIdProvider::failing(calls.clone()));
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;

    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    let e = block_on(auth_id::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::ProviderFailed(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn user_loader_can_return_none_when_user_missing() {
    let idp = Arc::new(FixedUserIdProvider::<i64>(Some(10)));
    let loader = Arc::new(CountingUserLoader::missing(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;

    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), Some(10));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), None);

    let e = block_on(auth_require::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));
}

#[test]
fn sign_in_out_updates_user_id_and_invalidates_cache() {
    let store = SharedIdStore::new(None);

    let idp = Arc::new(StoreUserIdProvider { store: store.clone() })
        as Arc<dyn CurrentUserIdProvider<i64>>;
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;
    let session = Arc::new(StoreUserIdSession { store: store.clone() })
        as Arc<dyn UserIdSession<i64>>;

    let engine = Arc::new(AuthEngine::new(idp, Some(loader), Some(session)));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), false);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), None);

    block_on(auth_sign_in_by_user_id::<i64, TestUser>(&42)).unwrap();
    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), true);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), Some(42));
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), Some(TestUser { id: 42 }));

    block_on(auth_sign_out::<i64, TestUser>()).unwrap();
    assert_eq!(block_on(auth_check::<i64, TestUser>()).unwrap(), false);
    assert_eq!(block_on(auth_id::<i64, TestUser>()).unwrap(), None);
    assert_eq!(block_on(auth_user::<i64, TestUser>()).unwrap(), None);
}

#[test]
fn sign_in_out_missing_session_is_an_error() {
    let idp = Arc::new(FixedUserIdProvider::<i64>(None));
    let loader = Arc::new(CountingUserLoader::new(Arc::new(AtomicUsize::new(0))))
        as Arc<dyn UserLoader<i64, TestUser>>;
    let engine = Arc::new(AuthEngine::new(idp, Some(loader), None));
    let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

    let e = block_on(auth_sign_in_by_user_id::<i64, TestUser>(&1)).unwrap_err();
    assert!(matches!(e, AuthError::MissingSession));

    let e = block_on(auth_sign_out::<i64, TestUser>()).unwrap_err();
    assert!(matches!(e, AuthError::MissingSession));
}
