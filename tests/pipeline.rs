use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use tetthys_auth::{
    AuthContext, AuthError, AuthSession, Authorizer, BoxFut, CredentialsVerifier, Policy, Principal,
};

// ---------- Test domain types ----------

#[derive(Debug, Clone)]
struct TestUser {
    id: u64,
    roles: HashSet<String>,
    perms: HashSet<String>,
}

impl TestUser {
    fn new(id: u64) -> Self {
        Self {
            id,
            roles: HashSet::new(),
            perms: HashSet::new(),
        }
    }

    fn with_role(mut self, role: &str) -> Self {
        self.roles.insert(role.to_string());
        self
    }

    fn with_perm(mut self, perm: &str) -> Self {
        self.perms.insert(perm.to_string());
        self
    }
}

impl Principal for TestUser {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }
}

// ---------- In-memory Session ----------

#[derive(Debug, Default)]
struct InMemorySession {
    // English comment: Keep currently signed-in user_id.
    signed_in: Mutex<Option<u64>>,
}

impl InMemorySession {
    fn new() -> Self {
        Self {
            signed_in: Mutex::new(None),
        }
    }

    fn get(&self) -> Option<u64> {
        *self.signed_in.lock().unwrap()
    }
}

impl AuthSession for InMemorySession {
    type UserId = u64;

    fn sign_in(&self, user_id: &Self::UserId) -> BoxFut<'_, Result<(), AuthError>> {
        let uid = *user_id;
        Box::pin(async move {
            *self.signed_in.lock().unwrap() = Some(uid);
            Ok(())
        })
    }

    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>> {
        Box::pin(async move {
            *self.signed_in.lock().unwrap() = None;
            Ok(())
        })
    }
}

// ---------- In-memory User Store ----------

#[derive(Debug, Default)]
struct UserStore {
    // English comment: Simple in-memory user repository.
    users: Mutex<HashMap<u64, TestUser>>,
}

impl UserStore {
    fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, user: TestUser) {
        self.users.lock().unwrap().insert(user.id(), user);
    }

    fn get(&self, id: u64) -> Option<TestUser> {
        self.users.lock().unwrap().get(&id).cloned()
    }
}

// ---------- AuthContext implementation ----------

#[derive(Clone)]
struct TestAuthContext {
    // English comment: Context wires session + user store.
    session: Arc<InMemorySession>,
    store: Arc<UserStore>,
}

impl TestAuthContext {
    fn new(session: Arc<InMemorySession>, store: Arc<UserStore>) -> Self {
        Self { session, store }
    }
}

impl AuthContext for TestAuthContext {
    type UserId = u64;
    type User = TestUser;

    fn current_user_id(&self) -> BoxFut<'_, Result<Option<Self::UserId>, AuthError>> {
        let session = self.session.clone();
        Box::pin(async move { Ok(session.get()) })
    }

    fn current_user(&self) -> BoxFut<'_, Result<Option<Self::User>, AuthError>> {
        let session = self.session.clone();
        let store = self.store.clone();
        Box::pin(async move {
            let uid = match session.get() {
                Some(uid) => uid,
                None => return Ok(None),
            };

            let user = store.get(uid).ok_or(AuthError::MissingSession)?;
            Ok(Some(user))
        })
    }

    fn require_user_id(&self) -> BoxFut<'_, Result<Self::UserId, AuthError>> {
        let session = self.session.clone();
        Box::pin(async move { session.get().ok_or(AuthError::Unauthenticated) })
    }

    fn require_user(&self) -> BoxFut<'_, Result<Self::User, AuthError>> {
        let session = self.session.clone();
        let store = self.store.clone();
        Box::pin(async move {
            let uid = session.get().ok_or(AuthError::Unauthenticated)?;
            store.get(uid).ok_or(AuthError::MissingSession)
        })
    }
}

// ---------- CredentialsVerifier (mock) ----------

#[derive(Debug, Clone)]
struct TestCredentials {
    username: String,
    password: String,
}

#[derive(Clone)]
struct MockCredentialsVerifier;

impl CredentialsVerifier for MockCredentialsVerifier {
    type Credentials = TestCredentials;
    type UserId = u64;

    fn verify(&self, credentials: &Self::Credentials) -> BoxFut<'_, Result<Self::UserId, AuthError>> {
        let u = credentials.username.clone();
        let p = credentials.password.clone();
        Box::pin(async move {
            // English comment: Extremely simplified verifier for tests.
            if u == "admin" && p == "pw" {
                Ok(1)
            } else if u == "user" && p == "pw" {
                Ok(2)
            } else {
                Err(AuthError::InvalidCredentials)
            }
        })
    }
}

// ---------- Authorizer (mock) ----------

#[derive(Clone)]
struct MockAuthorizer;

impl Authorizer for MockAuthorizer {
    type User = TestUser;

    fn has_role(&self, user: &Self::User, role: &str) -> BoxFut<'_, Result<bool, AuthError>> {
        let role = role.to_string();
        let u = user.clone();
        Box::pin(async move { Ok(u.roles.contains(&role)) })
    }

    fn has_permission(
        &self,
        user: &Self::User,
        permission: &str,
    ) -> BoxFut<'_, Result<bool, AuthError>> {
        let perm = permission.to_string();
        let u = user.clone();
        Box::pin(async move { Ok(u.perms.contains(&perm)) })
    }
}

// ---------- Policies ----------

#[derive(Clone)]
struct RequireAuthenticated;

impl Policy for RequireAuthenticated {
    type Ctx = TestAuthContext;

    fn check(&self, ctx: &Self::Ctx) -> BoxFut<'_, Result<(), AuthError>> {
        let ctx = ctx.clone();
        Box::pin(async move {
            ctx.require_user_id().await?;
            Ok(())
        })
    }
}

#[derive(Clone)]
struct RequireRole {
    role: String,
    authorizer: MockAuthorizer,
}

impl RequireRole {
    fn new(role: &str, authorizer: MockAuthorizer) -> Self {
        Self {
            role: role.to_string(),
            authorizer,
        }
    }
}

impl Policy for RequireRole {
    type Ctx = TestAuthContext;

    fn check(&self, ctx: &Self::Ctx) -> BoxFut<'_, Result<(), AuthError>> {
        let ctx = ctx.clone();
        let role = self.role.clone();
        let authz = self.authorizer.clone();
        Box::pin(async move {
            let user = ctx.require_user().await?;
            let ok = authz.has_role(&user, &role).await?;
            if ok {
                Ok(())
            } else {
                Err(AuthError::Forbidden)
            }
        })
    }
}

// ---------- Pipeline helper ----------

async fn auth_pipeline_login_and_authorize(
    ctx: &TestAuthContext,
    session: &InMemorySession,
    verifier: &MockCredentialsVerifier,
    creds: &TestCredentials,
    policy: &dyn Policy<Ctx = TestAuthContext>,
) -> Result<(), AuthError> {
    // English comment: 1) verify credentials => user_id
    let user_id = verifier.verify(creds).await?;

    // English comment: 2) persist session
    session.sign_in(&user_id).await?;

    // English comment: 3) enforce policy
    policy.check(ctx).await?;

    Ok(())
}

// ---------- Tests ----------

#[tokio::test]
async fn pipeline_denies_when_unauthenticated() {
    let session = Arc::new(InMemorySession::new());
    let store = Arc::new(UserStore::new());

    // English comment: Store a user, but do not sign in.
    store.insert(TestUser::new(1).with_role("admin"));

    let ctx = TestAuthContext::new(session.clone(), store);
    let policy = RequireAuthenticated;

    let err = policy.check(&ctx).await.unwrap_err();
    match err {
        AuthError::Unauthenticated => {}
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn pipeline_login_then_require_authenticated_passes() {
    let session = Arc::new(InMemorySession::new());
    let store = Arc::new(UserStore::new());

    store.insert(TestUser::new(1).with_role("admin"));

    let ctx = TestAuthContext::new(session.clone(), store);
    let verifier = MockCredentialsVerifier;
    let policy = RequireAuthenticated;

    let creds = TestCredentials {
        username: "admin".to_string(),
        password: "pw".to_string(),
    };

    let res = auth_pipeline_login_and_authorize(&ctx, &session, &verifier, &creds, &policy).await;
    assert!(res.is_ok());

    // English comment: Ensure session is set and user is loadable.
    let uid = ctx.current_user_id().await.unwrap();
    assert_eq!(uid, Some(1));

    let user = ctx.current_user().await.unwrap().unwrap();
    assert_eq!(user.id(), 1);
}

#[tokio::test]
async fn pipeline_login_but_missing_role_is_forbidden() {
    let session = Arc::new(InMemorySession::new());
    let store = Arc::new(UserStore::new());

    // English comment: user 2 exists but not admin.
    store.insert(TestUser::new(2).with_role("user"));

    let ctx = TestAuthContext::new(session.clone(), store);
    let verifier = MockCredentialsVerifier;

    let policy = RequireRole::new("admin", MockAuthorizer);

    let creds = TestCredentials {
        username: "user".to_string(),
        password: "pw".to_string(),
    };

    let err =
        auth_pipeline_login_and_authorize(&ctx, &session, &verifier, &creds, &policy)
            .await
            .unwrap_err();

    match err {
        AuthError::Forbidden => {}
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn pipeline_invalid_credentials_fails_before_session() {
    let session = Arc::new(InMemorySession::new());
    let store = Arc::new(UserStore::new());

    // English comment: Insert some users, but verifier decides.
    store.insert(TestUser::new(1).with_role("admin"));
    store.insert(TestUser::new(2).with_role("user"));

    let ctx = TestAuthContext::new(session.clone(), store);
    let verifier = MockCredentialsVerifier;
    let policy = RequireAuthenticated;

    let creds = TestCredentials {
        username: "admin".to_string(),
        password: "wrong".to_string(),
    };

    let err =
        auth_pipeline_login_and_authorize(&ctx, &session, &verifier, &creds, &policy)
            .await
            .unwrap_err();

    match err {
        AuthError::InvalidCredentials => {}
        other => panic!("unexpected error: {:?}", other),
    }

    // English comment: Ensure sign-in never happened.
    assert_eq!(ctx.current_user_id().await.unwrap(), None);
}

#[tokio::test]
async fn pipeline_sign_out_clears_context() {
    let session = Arc::new(InMemorySession::new());
    let store = Arc::new(UserStore::new());

    store.insert(TestUser::new(1).with_role("admin"));

    let ctx = TestAuthContext::new(session.clone(), store);

    session.sign_in(&1).await.unwrap();
    assert_eq!(ctx.current_user_id().await.unwrap(), Some(1));

    session.sign_out().await.unwrap();
    assert_eq!(ctx.current_user_id().await.unwrap(), None);

    let err = ctx.require_user_id().await.unwrap_err();
    match err {
        AuthError::Unauthenticated => {}
        other => panic!("unexpected error: {:?}", other),
    }
}
