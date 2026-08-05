pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("message truncated: wanted {wanted} bytes, {have} available")]
    Truncated { wanted: usize, have: usize },

    #[error("malformed message: {0}")]
    Malformed(&'static str),

    #[error("agent message is {0} bytes, over the {max} byte limit", max = crate::MAX_MESSAGE_LEN)]
    TooLarge(usize),

    #[error("no key matching the requested public blob")]
    NoSuchKey,

    #[error("key could not be parsed: {0}")]
    BadKey(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}
