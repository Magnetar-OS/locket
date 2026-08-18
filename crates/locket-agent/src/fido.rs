//! The real security key behind [`crate::sk::TokenSigner`].
//!
//! Split out behind the `fido` feature because it drags in `hidapi`, and an
//! agent that only ever serves ordinary keys should not need a C library to
//! build.

use crate::error::{Error, Result};
use crate::sk::{SkSignRequest, TokenAssertion, TokenSigner};

/// Drives an attached FIDO2 token through `locket-fido`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HardwareSigner;

impl TokenSigner for HardwareSigner {
    fn assert(&self, request: &SkSignRequest) -> Result<TokenAssertion> {
        let assertion = locket_fido::assert(
            &request.application,
            &request.key_handle,
            &request.message,
            request.pin.as_deref().map(String::as_str),
            request.user_verification,
        )
        .map_err(|e| Error::Signing(e.to_string()))?;

        Ok(TokenAssertion {
            auth_data: assertion.auth_data,
            signature: assertion.signature,
        })
    }

    fn describe(&self) -> &str {
        "security key"
    }
}
