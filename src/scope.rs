use std::any::Any;
use std::cell::RefCell;
use std::sync::Arc;

use crate::engine::AuthEngine;

thread_local! {
    // English comment: TLS is per-thread; we still keep Send+Sync here so downcast requires Engine: Send+Sync.
    static TLS_ENGINE: RefCell<Option<Arc<dyn Any + Send + Sync>>> = const { RefCell::new(None) };
}

/// TLS fallback scope (tests/non-Leptos environments).
pub struct ScopeGuard;

impl ScopeGuard {
    pub fn enter<UserId, User>(engine: Arc<AuthEngine<UserId, User>>) -> Self
    where
        UserId: Clone + Send + Sync + 'static,
        User: Clone + Send + Sync + 'static,
    {
        TLS_ENGINE.with(|cell| {
            *cell.borrow_mut() = Some(engine as Arc<dyn Any + Send + Sync>);
        });
        Self
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        TLS_ENGINE.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}

fn tls_get_engine<UserId, User>() -> Option<Arc<AuthEngine<UserId, User>>>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    TLS_ENGINE.with(|cell| {
        cell.borrow()
            .as_ref()
            // English comment: downcast requires T: Any + Send + Sync.
            .and_then(|any_arc| any_arc.clone().downcast::<AuthEngine<UserId, User>>().ok())
    })
}

#[cfg(feature = "leptos")]
fn leptos_get_engine<UserId, User>() -> Option<Arc<AuthEngine<UserId, User>>>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    use leptos::prelude::*;
    use_context::<Arc<AuthEngine<UserId, User>>>()
}

/// Resolve engine by priority:
/// 1) Leptos context (when enabled)
/// 2) TLS fallback (tests/non-Leptos)
pub fn get_engine<UserId, User>() -> Option<Arc<AuthEngine<UserId, User>>>
where
    UserId: Clone + Send + Sync + 'static,
    User: Clone + Send + Sync + 'static,
{
    #[cfg(feature = "leptos")]
    {
        if let Some(e) = leptos_get_engine::<UserId, User>() {
            return Some(e);
        }
    }

    tls_get_engine::<UserId, User>()
}
