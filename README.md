# tetthys-auth

**Simple Usage Guide for Leptos + Axum SSR**

`tetthys-auth` is a **minimal, framework-agnostic authentication core**.
In a **Leptos 0.8+ + Axum SSR** setup, it lets you access authentication state anywhere via async helpers, without globals or framework coupling.

This guide focuses only on **what you must implement and how to wire it**.

---

## What tetthys-auth Does (In One Sentence)

> It resolves the **current `user_id` per request**, optionally loads a **User record**, and exposes simple async helpers.

That’s it.

---

## What tetthys-auth Does NOT Do

* No `User` trait
* No roles or permissions
* No cookie parsing logic
* No database logic
* No middleware magic (you wire request-scoped injection yourself)

All of that stays in **your app**, not in this crate.

---

## Core Helpers You Will Use

Once wired, these work **anywhere** (SSR render, server functions, services):

```rust
auth_id::<UserId, User>().await?
auth_user::<UserId, User>().await?
auth_sign_in_by_user_id::<UserId, User>(&user_id).await?
auth_sign_out::<UserId, User>().await?
```

---

## Contracts You Implement (3 Small Pieces)

> Note: All trait objects are used behind `Arc<dyn ... + Send + Sync>`.
> Implementations must be thread-safe (or wrap internal state with `Arc<Mutex<...>>`, etc).

### 1) Resolve current `user_id` (per request)

```rust
use tetthys_auth::{AuthError, BoxFut, CurrentUserIdProvider};

struct MyUserIdProvider;

impl CurrentUserIdProvider<i64> for MyUserIdProvider {
    fn current_user_id(&self) -> BoxFut<'_, Result<Option<i64>, AuthError>> {
        Box::pin(async move {
            // Return Ok(Some(user_id)) if authenticated, Ok(None) if not.
            Ok(None)
        })
    }
}
```

Purpose:
➡ “Is this request authenticated? If yes, what is the user_id?”

**Where does request data come from?**
In SSR, the typical pattern is: **middleware extracts cookie/header → stores user_id into request-scoped state → provider reads from that state** (see “Wiring” section).

---

### 2) Load the User by `user_id` (optional but recommended)

```rust
use tetthys_auth::{AuthError, BoxFut, UserLoader};

#[derive(Clone)]
struct User {
    id: i64,
}

struct MyUserRepo;

impl UserLoader<i64, User> for MyUserRepo {
    fn load_user(&self, user_id: &i64) -> BoxFut<'_, Result<Option<User>, AuthError>> {
        let id = *user_id;
        Box::pin(async move {
            // SELECT * FROM users WHERE id = ?
            Ok(Some(User { id }))
        })
    }
}
```

Notes:

* Returning `None` is valid (deleted user, stale session).
* In that case `auth_user()` returns `None`.

---

### 3) Mutate the session using `user_id`

```rust
use tetthys_auth::{AuthError, BoxFut, UserIdSession};

struct MySession;

impl UserIdSession<i64> for MySession {
    fn sign_in_by_user_id(&self, user_id: &i64) -> BoxFut<'_, Result<(), AuthError>> {
        let id = *user_id;
        Box::pin(async move {
            // Persist session (cookie / DB row / etc)
            // Example: set "sid" cookie + insert session row containing user_id
            let _ = id;
            Ok(())
        })
    }

    fn sign_out(&self) -> BoxFut<'_, Result<(), AuthError>> {
        Box::pin(async move {
            // Clear session (remove cookie / delete DB row / etc)
            Ok(())
        })
    }
}
```

Purpose:
➡ “Persist or clear authentication state.”

---

## Wiring Model (Important)

`tetthys-auth` needs an `AuthEngine<UserId, User>` **available in the current request scope**.

Engine lookup priority is:

1. Leptos context (when enabled)
2. TLS fallback (tests / non-Leptos environments)

In real Axum SSR, you typically do **request middleware injection**, so every request gets its own engine (and per-request cache).

---

## Wiring in Axum SSR (Recommended Pattern)

### A) Middleware: build a request-scoped engine and enter scope

Pseudo-pattern:

* Parse cookie/header from the request
* Create a request-scoped provider that returns the parsed user id
* Construct `AuthEngine`
* Enter scope for the duration of the request

Example (conceptual; keep your own cookie/db logic in app):

```rust
use std::sync::Arc;
use axum::{http::Request, middleware::Next, response::Response};
use tetthys_auth::{AuthEngine, FixedUserIdProvider, UserLoader, UserIdSession};

pub async fn auth_middleware<B, UserId, User>(
    req: Request<B>,
    next: Next<B>,
    user_loader: Option<Arc<dyn UserLoader<UserId, User> + Send + Sync>>,
    session: Option<Arc<dyn UserIdSession<UserId> + Send + Sync>>,
    user_id: Option<UserId>,
) -> Response
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    // 1) user_id is computed from cookie/header/etc in *your app*.
    let idp = Arc::new(FixedUserIdProvider::new(user_id))
        as Arc<dyn tetthys_auth::CurrentUserIdProvider<UserId> + Send + Sync>;

    // 2) per-request engine
    let engine = Arc::new(AuthEngine::new(idp, user_loader, session));

    // 3) enter TLS scope for this request
    let _guard = tetthys_auth::scope::ScopeGuard::enter(engine);

    next.run(req).await
}
```

This makes auth helpers work inside request handling, SSR rendering, and server functions (as long as they run within the same request scope).

---

## Using Auth Helpers (Examples)

### Get current user id

```rust
let user_id = auth_id::<i64, User>().await?;
```

### Get current user

```rust
if let Some(user) = auth_user::<i64, User>().await? {
    // authenticated
}
```

### Require authentication

```rust
let user = auth_require::<i64, User>().await?;
```

### Sign in

```rust
auth_sign_in_by_user_id::<i64, User>(&user_id).await?;
```

### Sign out

```rust
auth_sign_out::<i64, User>().await?;
```

---

## Testing Without Leptos/Axum

For tests, enter TLS scope explicitly:

```rust
use std::sync::Arc;
use tetthys_auth::{AuthEngine, FixedUserIdProvider};

let idp = Arc::new(FixedUserIdProvider::<i64>::new(Some(1)));
let engine = Arc::new(AuthEngine::new(idp, None, None));
let _g = tetthys_auth::scope::ScopeGuard::enter(engine);

// Now auth_* helpers work.
```

---

## Mental Model (Keep This)

* Authentication = **user_id exists or not**
* Session = **store user_id**
* User = **optional materialization**
* Everything is **request-scoped**
* No globals, no magic (you inject scope per request)

---

## Common Errors

| Error             | Meaning                                                             |
| ----------------- | ------------------------------------------------------------------- |
| `MissingContext`  | Engine not injected into current scope (middleware/context missing) |
| `Unauthenticated` | No user_id                                                          |
| `MissingSession`  | sign-in/out called but engine has no `UserIdSession` configured     |

---

## That’s It

If you understand:

* “I resolve user_id”
* “I load user by id”
* “I store/clear user_id”

…then you understand `tetthys-auth`.