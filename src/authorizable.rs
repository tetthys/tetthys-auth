use std::borrow::Cow;

pub type Ability<'a> = Cow<'a, str>;

#[derive(Debug, Clone)]
pub struct Authorization {
    pub allowed: bool,
    pub reason: Option<String>,
}

impl Authorization {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
        }
    }
}

pub trait Authorizable: Clone + Send + Sync + 'static {
    fn roles(&self) -> Vec<String> {
        vec![]
    }

    fn permissions(&self) -> Vec<String> {
        vec![]
    }

    fn has_role(&self, role: &str) -> bool {
        self.roles().iter().any(|r| r == role)
    }

    fn has_permission(&self, perm: &str) -> bool {
        self.permissions().iter().any(|p| p == perm)
    }

    // English comment: default policy - allowed if permission exists OR role "admin" exists.
    fn can(&self, ability: &str) -> bool {
        self.has_permission(ability) || self.has_role("admin")
    }

    fn authorize(&self, ability: &str) -> Authorization {
        if self.can(ability) {
            Authorization::allow()
        } else {
            Authorization::deny("forbidden")
        }
    }
}
