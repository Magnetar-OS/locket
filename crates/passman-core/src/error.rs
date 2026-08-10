use std::path::PathBuf;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault at {path} is not a passman vault (bad magic)")]
    NotAVault { path: PathBuf },

    #[error("vault format version {found} is newer than this build supports (max {supported})")]
    UnsupportedVersion { found: u16, supported: u16 },

    /// No key slot accepted the supplied factor. Almost always a typo.
    ///
    /// Kept distinct from [`Error::Unauthenticated`] so a failure to unwrap
    /// the key reads differently from a failure to authenticate the body:
    /// conflating the two turned a format-compatibility bug into an
    /// indistinguishable "or the vault has been tampered with".
    #[error("incorrect passphrase")]
    WrongPassphrase,

    #[error("the vault could not be authenticated; it may have been tampered with")]
    Unauthenticated,

    #[error("the vault is locked")]
    Locked,

    #[error("no item with id {0}")]
    NoSuchItem(uuid::Uuid),

    #[error("invalid Argon2 parameters: {0}")]
    KdfParams(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("malformed base64 in vault file field `{field}`")]
    Base64 { field: &'static str },

    #[error("field `{field}` has length {found}, expected {expected}")]
    FieldLength {
        field: &'static str,
        found: usize,
        expected: usize,
    },

    #[error("could not gather randomness from the operating system: {0}")]
    Random(String),

    #[error("vault contents are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Io2(#[from] std::io::Error),

    #[error("could not determine the user's data directory")]
    NoDataDir,

    #[error("invalid TOTP secret: {0}")]
    Totp(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Random(e.to_string())
    }
}
