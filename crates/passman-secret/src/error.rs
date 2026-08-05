pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("session transport error: {0}")]
    Crypto(String),

    #[error("unsupported session algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("no such session: {0}")]
    NoSession(String),

    #[error("no such object: {0}")]
    NoSuchObject(String),

    #[error("the collection is locked")]
    Locked,

    #[error("vault error: {0}")]
    Vault(#[from] passman_core::Error),

    #[error("d-bus error: {0}")]
    Dbus(#[from] zbus::Error),

    #[error("{0}")]
    Other(String),
}

/// Map onto the error names the Secret Service spec defines, so `libsecret`
/// clients see the errors they already know how to handle.
impl From<Error> for zbus::fdo::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::UnsupportedAlgorithm(_) => {
                zbus::fdo::Error::NotSupported(e.to_string())
            }
            Error::NoSession(_) | Error::NoSuchObject(_) => {
                zbus::fdo::Error::Failed(format!("org.freedesktop.Secret.Error.NoSuchObject: {e}"))
            }
            Error::Locked => {
                zbus::fdo::Error::Failed(format!("org.freedesktop.Secret.Error.IsLocked: {e}"))
            }
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}
