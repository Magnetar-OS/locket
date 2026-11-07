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
    Vault(#[from] locket_core::Error),

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
///
/// [`zbus::DBusError`] is implemented by hand rather than derived. The
/// derive's catch-all variant replies under `org.freedesktop.zbus.Error`
/// whatever it holds, so a refusal the specification names with a standard
/// error — `NotSupported` for `ChangeLock` and for an unknown session
/// algorithm, `AccessDenied` for deleting locket's own collection — reached
/// clients under a name none of them knows.
#[derive(Debug)]
pub enum SecretError {
    /// Anything without a Secret Service name, under the standard name zbus
    /// gives it: `org.freedesktop.DBus.Error.NotSupported`, `AccessDenied`,
    /// `Failed` and so on.
    Other(StandardError),
    /// The collection or item is locked; unlock it and retry.
    IsLocked(String),
    /// The session or object path does not exist.
    NoSession(String),
    NoSuchObject(String),
}

/// A D-Bus error under its own name, as zbus replies with it.
pub struct StandardError(zbus::BoxDBusError);

impl std::fmt::Debug for StandardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl zbus::DBusError for SecretError {
    fn name(&self) -> zbus::names::ErrorName<'_> {
        let name = match self {
            SecretError::Other(standard) => return standard.0.name(),
            SecretError::IsLocked(_) => "org.freedesktop.Secret.Error.IsLocked",
            SecretError::NoSession(_) => "org.freedesktop.Secret.Error.NoSession",
            SecretError::NoSuchObject(_) => "org.freedesktop.Secret.Error.NoSuchObject",
        };
        zbus::names::ErrorName::from_static_str_unchecked(name)
    }

    fn description(&self) -> Option<&str> {
        match self {
            SecretError::Other(standard) => standard.0.description(),
            SecretError::IsLocked(why)
            | SecretError::NoSession(why)
            | SecretError::NoSuchObject(why) => Some(why),
        }
    }

    fn create_reply(
        &self,
        call: &zbus::message::Header<'_>,
    ) -> zbus::Result<zbus::message::Message> {
        match self {
            SecretError::Other(standard) => standard.0.create_reply(call),
            SecretError::IsLocked(why)
            | SecretError::NoSession(why)
            | SecretError::NoSuchObject(why) => {
                zbus::message::Message::error(call, self.name()).build(&(why,))
            }
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use zbus::DBusError as _;
        write!(f, "{}: {}", self.name(), self.description().unwrap_or(""))
    }
}

impl std::error::Error for SecretError {}

/// What the object server hands back when it fails on its own — a body that
/// does not deserialize, say — under the name zbus would reply with.
impl From<zbus::Error> for SecretError {
    fn from(e: zbus::Error) -> Self {
        SecretError::Other(StandardError(e.into()))
    }
}

impl From<zbus::fdo::Error> for SecretError {
    fn from(e: zbus::fdo::Error) -> Self {
        SecretError::Other(StandardError(e.into()))
    }
}

impl From<Error> for SecretError {
    fn from(e: Error) -> Self {
        match e {
            Error::Locked => SecretError::IsLocked(e.to_string()),
            Error::NoSession(_) => SecretError::NoSession(e.to_string()),
            Error::NoSuchObject(_) => SecretError::NoSuchObject(e.to_string()),
            // `NotSupported` for an unknown algorithm, `Failed` for the rest.
            other => zbus::fdo::Error::from(other).into(),
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
