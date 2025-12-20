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

- No `User` trait
- No roles or permissions
- No cookie parsing logic
- No database logic
- No middleware magic

All of that stays in **your app**, not in this crate.

---

## Core Helpers You Will Use

Once wired, these work **anywhere** (SSR render, server functions, services):

```rust
auth_id::<UserId, User>().await?
auth_user::<UserId, User>().await?
auth_sign_in_by_user_id::<UserId, User>(&user_id).await?
auth_sign_out::<UserId, User>().await?
````

---

## What You Need to Implement (3 Small Pieces)

### 1) Resolve `user_id` from the request

```rust
use axum::body::Body;
use axum::extract::Request;
use tetthys_auth::AuthError;

struct MyUserIdResolver;

impl RequestUserIdResolver<i64> for MyUserIdResolver {
    fn resolve_user_id(
        &self,
        req: &Request<Body>,
    ) -> Result<Option<i64>, AuthError> {
        // Read cookie / header / JWT
        Ok(None)
    }
}
```

Purpose:
➡ “Is this request authenticated? If yes, what is the user_id?”

---

### 2) Load the User by `user_id` (optional but recommended)

```rust
use tetthys_auth::{AuthError, BoxFut};

struct MyUserRepo;

impl RepoUserLoader<i64, User> for MyUserRepo {
    fn find_by_user_id(
        &self,
        user_id: &i64,
    ) -> BoxFut<'_, Result<Option<User>, AuthError>> {
        Box::pin(async move {
            // SELECT * FROM users WHERE id = ?
            Ok(Some(User { id: *user_id }))
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
use tetthys_auth::{AuthError, BoxFut};

struct MySessionMutator;

impl RequestUserIdSessionMutator<i64> for MySessionMutator {
    fn sign_in_by_user_id(
        &self,
        req: &Request<Body>,
        user_id: &i64,
    ) -> BoxFut<'_, Result<(), AuthError>> {
        Box::pin(async {
            // Set cookie / session row
            Ok(())
        })
    }

    fn sign_out(
        &self,
        req: &Request<Body>,
    ) -> BoxFut<'_, Result<(), AuthError>> {
        Box::pin(async {
            // Clear cookie / delete session row
            Ok(())
        })
    }
}
```

Purpose:
➡ “Persist or clear authentication state.”

---

## Wiring in Axum (One Time)

Create shared adapter state:

```rust
use std::sync::Arc;
use tetthys_auth::adapters::leptos_axum_ssr::AuthAdapterState;

let auth_state = AuthAdapterState::<i64, User>::new(
    Arc::new(MyUserIdResolver),
    Arc::new(MyUserRepo),
    Some(Arc::new(MySessionMutator)),
);
```

Attach it to your Axum app state.

---

## Server Functions Route (Required)

```rust
use axum::routing::post;
use tetthys_auth::adapters::leptos_axum_ssr::leptos_server_fns_handler_with_auth;

Router::new()
    .route(
        "/api/*fn_name",
        post(leptos_server_fns_handler_with_auth::<i64, User, AppState>),
    )
    .with_state(app_state);
```

This makes auth helpers work inside `#[server]` functions.

---

## SSR Rendering Route (Required)

```rust
use tetthys_auth::adapters::leptos_axum_ssr::leptos_ssr_render_handler_with_auth;

Router::new().fallback(
    leptos_ssr_render_handler_with_auth::<i64, User, AppState, _>(
        app_state,
        leptos_options,
        || view! { <App/> },
    ),
);
```

This makes auth helpers work during SSR rendering.

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

## Mental Model (Keep This)

* Authentication = **user_id exists or not**
* Session = **store user_id**
* User = **optional materialization**
* Everything is **request-scoped**
* No globals, no magic

---

## Common Errors

| Error             | Meaning                                    |
| ----------------- | ------------------------------------------ |
| `MissingContext`  | Auth not injected into SSR/server-fns      |
| `Unauthenticated` | No user_id                                 |
| `MissingSession`  | sign-in/out called without session mutator |

---

## That’s It

If you understand:

* “I resolve user_id”
* “I load user by id”
* “I store/clear user_id”

…then you understand `tetthys-auth`.