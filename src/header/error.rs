use alloc::string::String;

#[derive(Debug, thiserror_no_std::Error)]
pub enum Error {
    ExpectedProtected,
    NotDisjoint,
    NotAnObject,
    NotFound,
    ForbiddenHeader(String),
    MissingHeader(String),
    EmptyCriticalHeaders,
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}
