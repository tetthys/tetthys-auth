pub trait Authenticatable: Clone + Send + Sync + 'static {
    type Id: Clone + Send + Sync + 'static;

    fn id(&self) -> Self::Id;

    // English comment: Optional convenience hook.
    fn display_name(&self) -> Option<String> {
        None
    }
}
