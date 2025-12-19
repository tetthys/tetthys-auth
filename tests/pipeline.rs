use std::cell::{Cell, RefCell};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use tetthys_auth::{
    auth_assert, auth_can, auth_can_any, auth_check, auth_has_any_role, auth_has_role, auth_id,
    auth_require, auth_require_id, auth_sign_in, auth_sign_out, auth_user, AuthContext,
    AuthContextAccessor, AuthError, Authenticatable, Authorizable, AuthProvider, AuthSession,
    AuthSessionAccessor, ChainProvider, FixedProvider,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestUser {
    id: u64,
    roles: Vec<String>,
    perms: Vec<String>,
}

impl Authenticatable for TestUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn display_name(&self) -> Option<String> {
        Some(format!("user#{}", self.id))
    }
}

impl Authorizable for TestUser {
    fn roles(&self) -> Vec<String> {
        self.roles.clone()
    }

    fn permissions(&self) -> Vec<String> {
        self.perms.clone()
    }
}

// ------------------------------
// Test request-scope adapters
// ------------------------------
//
// IMPORTANT:
// - AuthContext pointer can be stored as *const () because it's a thin pointer.
// - dyn AuthSession is a fat pointer; do NOT erase it into *const ().
//   Store it directly using RefCell<Option<&'static dyn ...>>.
//

thread_local! {
    static CTX_PTR: Cell<*const ()> = const { Cell::new(std::ptr::null()) };
    static SESS: RefCell<Option<&'static dyn AuthSession<TestUser>>> = const { RefCell::new(None) };
}

fn set_ctx_for_test(ctx: AuthContext<TestUser>) {
    let leaked: &'static AuthContext<TestUser> = Box::leak(Box::new(ctx));
    CTX_PTR.with(|c| c.set(leaked as *const _ as *const ()));
}

fn set_session_for_test(sess: impl AuthSession<TestUser> + 'static) {
    let leaked: &'static dyn AuthSession<TestUser> = Box::leak(Box::new(sess));
    SESS.with(|s| *s.borrow_mut() = Some(leaked));
}

fn clear_scope_for_test() {
    CTX_PTR.with(|c| c.set(std::ptr::null()));
    SESS.with(|s| *s.borrow_mut() = None);
}

impl AuthContextAccessor<TestUser> for () {
    fn get() -> Option<&'static AuthContext<TestUser>> {
        CTX_PTR.with(|c| {
            let p = c.get();
            if p.is_null() {
                None
            } else {
                Some(unsafe { &*(p as *const AuthContext<TestUser>) })
            }
        })
    }
}

impl AuthSessionAccessor<TestUser> for () {
    fn get() -> Option<&'static dyn AuthSession<TestUser>> {
        SESS.with(|s| *s.borrow())
    }
}

// ------------------------------
// Providers for pipeline tests
// ------------------------------

struct CountingProvider {
    calls: Arc<AtomicUsize>,
    user: Option<TestUser>,
    fail: bool,
}

impl CountingProvider {
    fn new(calls: Arc<AtomicUsize>, user: Option<TestUser>) -> Self {
        Self {
            calls,
            user,
            fail: false,
        }
    }

    fn failing(calls: Arc<AtomicUsize>) -> Self {
        Self {
            calls,
            user: None,
            fail: true,
        }
    }
}

impl AuthProvider<TestUser> for CountingProvider {
    fn user(&self) -> Result<Option<TestUser>, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(AuthError::ProviderFailed("boom".into()));
        }
        Ok(self.user.clone())
    }
}

// Shared "session store" to validate sign-in/out pipeline.
#[derive(Clone)]
struct SharedAuthStore {
    user: Arc<Mutex<Option<TestUser>>>,
}

impl SharedAuthStore {
    fn new(initial: Option<TestUser>) -> Self {
        Self {
            user: Arc::new(Mutex::new(initial)),
        }
    }
}

struct SharedProvider {
    store: SharedAuthStore,
}

impl AuthProvider<TestUser> for SharedProvider {
    fn user(&self) -> Result<Option<TestUser>, AuthError> {
        let g = self
            .store
            .user
            .lock()
            .map_err(|_| AuthError::ProviderFailed("store poisoned".into()))?;
        Ok(g.clone())
    }
}

struct SharedSession {
    store: SharedAuthStore,
}

impl AuthSession<TestUser> for SharedSession {
    fn sign_in(&self, user: &TestUser) -> Result<(), AuthError> {
        let mut g = self
            .store
            .user
            .lock()
            .map_err(|_| AuthError::ProviderFailed("store poisoned".into()))?;
        *g = Some(user.clone());
        Ok(())
    }

    fn sign_out(&self) -> Result<(), AuthError> {
        let mut g = self
            .store
            .user
            .lock()
            .map_err(|_| AuthError::ProviderFailed("store poisoned".into()))?;
        *g = None;
        Ok(())
    }
}

// ------------------------------
// Tests
// ------------------------------

#[test]
fn pipeline_unauthenticated_basics() {
    clear_scope_for_test();

    let e = auth_user::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::MissingContext));

    set_ctx_for_test(AuthContext::new(Box::new(FixedProvider::<TestUser>(None))));

    assert_eq!(auth_check::<TestUser>().unwrap(), false);
    assert_eq!(auth_user::<TestUser>().unwrap(), None);

    let e = auth_require::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));

    let e = auth_assert::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));

    assert_eq!(auth_id::<TestUser>().unwrap(), None);

    let e = auth_require_id::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::Unauthenticated));

    assert_eq!(auth_can::<TestUser>("posts.write").unwrap(), false);
    assert_eq!(
        auth_can_any::<TestUser>(&["posts.write", "posts.read"]).unwrap(),
        false
    );
    assert_eq!(auth_has_role::<TestUser>("admin").unwrap(), false);
    assert_eq!(auth_has_any_role::<TestUser>(&["admin", "staff"]).unwrap(), false);
}

#[test]
fn pipeline_authenticated_basics() {
    let u = TestUser {
        id: 7,
        roles: vec!["staff".into()],
        perms: vec!["posts.read".into(), "posts.write".into()],
    };

    set_ctx_for_test(AuthContext::new(Box::new(FixedProvider(Some(u.clone())))));

    assert_eq!(auth_check::<TestUser>().unwrap(), true);
    assert_eq!(auth_user::<TestUser>().unwrap(), Some(u.clone()));
    assert_eq!(auth_require::<TestUser>().unwrap(), u);
    assert_eq!(auth_id::<TestUser>().unwrap(), Some(7));
    assert_eq!(auth_require_id::<TestUser>().unwrap(), 7);

    assert_eq!(auth_can::<TestUser>("posts.write").unwrap(), true);
    assert_eq!(auth_can::<TestUser>("orders.refund").unwrap(), false);
    assert_eq!(
        auth_can_any::<TestUser>(&["orders.refund", "posts.read"]).unwrap(),
        true
    );

    assert_eq!(auth_has_role::<TestUser>("staff").unwrap(), true);
    assert_eq!(auth_has_role::<TestUser>("admin").unwrap(), false);
    assert_eq!(
        auth_has_any_role::<TestUser>(&["admin", "staff"]).unwrap(),
        true
    );
}

#[test]
fn pipeline_admin_role_allows_by_default_can_policy() {
    let u = TestUser {
        id: 1,
        roles: vec!["admin".into()],
        perms: vec![],
    };

    set_ctx_for_test(AuthContext::new(Box::new(FixedProvider(Some(u)))));
    assert_eq!(auth_can::<TestUser>("anything.at.all").unwrap(), true);
}

#[test]
fn provider_chain_pipeline_order_and_fallback() {
    let calls_a = Arc::new(AtomicUsize::new(0));
    let calls_b = Arc::new(AtomicUsize::new(0));

    let p1 = Box::new(CountingProvider::new(calls_a.clone(), None));
    let u = TestUser {
        id: 9,
        roles: vec![],
        perms: vec!["posts.read".into()],
    };
    let p2 = Box::new(CountingProvider::new(calls_b.clone(), Some(u.clone())));

    let chain = ChainProvider::new(vec![p1, p2]);
    set_ctx_for_test(AuthContext::new(Box::new(chain)));

    assert_eq!(auth_check::<TestUser>().unwrap(), true);
    assert_eq!(auth_user::<TestUser>().unwrap(), Some(u));

    assert_eq!(calls_a.load(Ordering::SeqCst), 1);
    assert_eq!(calls_b.load(Ordering::SeqCst), 1);
}

#[test]
fn context_caches_provider_result_per_request_scope() {
    let calls = Arc::new(AtomicUsize::new(0));
    let u = TestUser {
        id: 3,
        roles: vec![],
        perms: vec!["posts.read".into()],
    };

    set_ctx_for_test(AuthContext::new(Box::new(CountingProvider::new(
        calls.clone(),
        Some(u.clone()),
    ))));

    assert_eq!(auth_check::<TestUser>().unwrap(), true);
    assert_eq!(auth_user::<TestUser>().unwrap(), Some(u.clone()));
    assert_eq!(auth_id::<TestUser>().unwrap(), Some(3));
    assert_eq!(auth_can::<TestUser>("posts.read").unwrap(), true);

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_errors_propagate_through_helpers() {
    let calls = Arc::new(AtomicUsize::new(0));

    set_ctx_for_test(AuthContext::new(Box::new(CountingProvider::failing(
        calls.clone(),
    ))));

    let e = auth_user::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::ProviderFailed(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn sign_in_out_pipeline_updates_user_and_invalidates_cache() {
    let store = SharedAuthStore::new(None);

    set_ctx_for_test(AuthContext::new(Box::new(SharedProvider { store: store.clone() })));
    set_session_for_test(SharedSession { store: store.clone() });

    assert_eq!(auth_check::<TestUser>().unwrap(), false);
    assert_eq!(auth_user::<TestUser>().unwrap(), None);

    let u = TestUser {
        id: 42,
        roles: vec!["staff".into()],
        perms: vec!["posts.read".into()],
    };

    auth_sign_in::<TestUser>(&u).unwrap();
    assert_eq!(auth_check::<TestUser>().unwrap(), true);
    assert_eq!(auth_user::<TestUser>().unwrap(), Some(u.clone()));

    auth_sign_out::<TestUser>().unwrap();
    assert_eq!(auth_check::<TestUser>().unwrap(), false);
    assert_eq!(auth_user::<TestUser>().unwrap(), None);
}

#[test]
fn sign_in_out_missing_session_is_an_error() {
    let store = SharedAuthStore::new(None);

    set_ctx_for_test(AuthContext::new(Box::new(SharedProvider { store })));
    SESS.with(|s| *s.borrow_mut() = None);

    let u = TestUser {
        id: 1,
        roles: vec![],
        perms: vec![],
    };

    let e = auth_sign_in::<TestUser>(&u).unwrap_err();
    assert!(matches!(e, AuthError::MissingSession));

    let e = auth_sign_out::<TestUser>().unwrap_err();
    assert!(matches!(e, AuthError::MissingSession));
}
