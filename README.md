# tetthys-auth

Framework-agnostic authentication/authorization core for Rust applications.

---

## Core Concepts

`tetthys-auth` separates authentication into clear responsibilities:

| Responsibility | Trait |
|----------------|------|
| User identity  | `Authenticatable` |
| Roles / permissions | `Authorizable` |
| Load current user | `AuthProvider` |
| Mutate login state | `AuthSession` |
| Request cache & pipeline | `AuthContext` |

---

## Defining a User

Your user type must implement `Authenticatable`.  
To use authorization helpers, also implement `Authorizable`.

```rust
#[derive(Clone)]
struct User {
    id: u64,
    roles: Vec<String>,
    perms: Vec<String>,
}
````

### Authenticatable

```rust
use tetthys_auth::Authenticatable;

impl Authenticatable for User {
    type Id = u64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn display_name(&self) -> Option<String> {
        Some(format!("user#{}", self.id))
    }
}
```

### Authorizable

```rust
use tetthys_auth::Authorizable;

impl Authorizable for User {
    fn roles(&self) -> Vec<String> {
        self.roles.clone()
    }

    fn permissions(&self) -> Vec<String> {
        self.perms.clone()
    }
}
```

---

## AuthProvider

An `AuthProvider` is responsible for **resolving the current user**.

```rust
use tetthys_auth::{AuthProvider, AuthError};

struct FixedProvider {
    user: Option<User>,
}

impl AuthProvider<User> for FixedProvider {
    fn user(&self) -> Result<Option<User>, AuthError> {
        Ok(self.user.clone())
    }
}
```

Providers may:

* Return `Ok(None)` for unauthenticated requests
* Return `Err(AuthError::ProviderFailed(_))` on failure

---

## AuthContext (Request Scope)

`AuthContext` represents **one request**.

It:

* Owns the provider
* Caches the resolved user
* Is invalidated on sign-in / sign-out

You must expose it via `AuthContextAccessor`.

### Minimal test / thread-local example

```rust
use std::cell::Cell;
use tetthys_auth::{AuthContext, AuthContextAccessor};

thread_local! {
    static CTX_PTR: Cell<*const ()> = Cell::new(std::ptr::null());
}

fn set_ctx(ctx: AuthContext<User>) {
    let leaked: &'static AuthContext<User> = Box::leak(Box::new(ctx));
    CTX_PTR.with(|c| c.set(leaked as *const _ as *const ()));
}

impl AuthContextAccessor<User> for () {
    fn get() -> Option<&'static AuthContext<User>> {
        CTX_PTR.with(|c| {
            let p = c.get();
            if p.is_null() {
                None
            } else {
                Some(unsafe { &*(p as *const AuthContext<User>) })
            }
        })
    }
}
```

---

## Authentication Helpers

All helpers return `Result<_, AuthError>`.

### Auth state

```rust
auth_check::<User>()?      // bool
auth_user::<User>()?       // Option<User>
auth_require::<User>()?    // User or Unauthenticated
```

### User ID

```rust
auth_id::<User>()?         // Option<User::Id>
auth_require_id::<User>()? // User::Id or Unauthenticated
```

---

## Authorization Helpers

### Permissions

```rust
auth_can::<User>("posts.write")?
auth_can_any::<User>(&["posts.read", "posts.write"])?
```

If the user has the `admin` role, all permissions are allowed by default.

### Roles

```rust
auth_has_role::<User>("admin")?
auth_has_any_role::<User>(&["admin", "staff"])?
```

---

## Provider Chaining

Multiple providers can be evaluated in order.

```rust
use tetthys_auth::ChainProvider;

let chain = ChainProvider::new(vec![
    Box::new(provider_a),
    Box::new(provider_b),
]);

set_ctx(AuthContext::new(Box::new(chain)));
```

Behavior:

* Providers are queried in order
* The first `Some(user)` wins
* Results are cached per request

---

## Request-Level Caching

Within a single request:

```rust
auth_user::<User>()?;
auth_id::<User>()?;
auth_can::<User>("posts.read")?;
```

The provider is called **only once**.

---

## AuthSession (Sign-in / Sign-out)

`AuthSession` mutates the authentication state.

```rust
use tetthys_auth::{AuthSession, AuthError};

struct Session;

impl AuthSession<User> for Session {
    fn sign_in(&self, user: &User) -> Result<(), AuthError> {
        Ok(())
    }

    fn sign_out(&self) -> Result<(), AuthError> {
        Ok(())
    }
}
```

You must expose it via `AuthSessionAccessor`.

```rust
use std::cell::RefCell;
use tetthys_auth::AuthSessionAccessor;

thread_local! {
    static SESS: RefCell<Option<&'static dyn AuthSession<User>>> = RefCell::new(None);
}

impl AuthSessionAccessor<User> for () {
    fn get() -> Option<&'static dyn AuthSession<User>> {
        SESS.with(|s| *s.borrow())
    }
}
```

---

## Sign In / Sign Out

```rust
auth_sign_in::<User>(&user)?;
auth_sign_out::<User>()?;
```

Notes:

* Missing session → `AuthError::MissingSession`
* Automatically invalidates `AuthContext` cache

---

## Errors

```rust
AuthError::MissingContext
AuthError::MissingSession
AuthError::Unauthenticated
AuthError::ProviderFailed(String)
```

---

## Quick Start Example

```rust
let user = User {
    id: 1,
    roles: vec!["admin".into()],
    perms: vec![],
};

set_ctx(AuthContext::new(Box::new(FixedProvider {
    user: Some(user),
})));

assert!(auth_check::<User>()?);
assert!(auth_can::<User>("anything.at.all")?);
```

---

## Design Summary

* No global singletons
* Explicit request boundaries
* Provider-based authentication
* Clear separation of concerns
* Highly testable
