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

/// The error names the Secret Service specification defines.
///
/// These must be real D-Bus error *names*, not a `Failed` carrying the name in
/// its message: `libsecret` branches on the name to decide whether to prompt
/// for an unlock or give up. Putting `org.freedesktop.Secret.Error.IsLocked`
/// in the text of a `org.freedesktop.DBus.Error.Failed` looks right in a log
/// and is invisible to every client.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretError {
    /// Anything without a more specific name.
    #[zbus(error)]
    ZBus(zbus::Error),
    /// The collection or item is locked; unlock it and retry.
    IsLocked(String),
    /// The session or object path does not exist.
    NoSession(String),
    NoSuchObject(String),
}

impl From<Error> for SecretError {
    fn from(e: Error) -> Self {
        match e {
            Error::Locked => SecretError::IsLocked(e.to_string()),
            Error::NoSession(_) => SecretError::NoSession(e.to_string()),
            Error::NoSuchObject(_) => SecretError::NoSuchObject(e.to_string()),
            other => SecretError::ZBus(zbus::Error::Failure(other.to_string())),
        }
    }
}

/// Kept for the paths where a plain fdo error is the right answer.
impl From<Error> for zbus::fdo::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::UnsupportedAlgorithm(_) => zbus::fdo::Error::NotSupported(e.to_string()),
            Error::NoSession(_) | Error::NoSuchObject(_) => {
                zbus::fdo::Error::UnknownObject(e.to_string())
            }
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}
