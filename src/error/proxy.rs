//! Proxy (auth-url) authentication errors

use thiserror::Error;

/// Proxy authentication-related errors
#[derive(Debug, Clone, Error)]
pub enum ProxyError {
    #[error("Missing auth_url code in (query string or cookie)")]
    MissingCode,

    #[error("Could not parse X-Original-URL header (it is set but not valid)")]
    CouldNotParseXOriginalURIHeader,

    #[error("The provided return destination URL (`rd` query parameter) doesn't have a an origin that is allowed in the config")]
    InvalidReturnDestinationUrl,

    #[error("Invalid origin header")]
    InvalidOriginHeader,

    #[error("Proxy authentication error: {message}")]
    Authentication { message: String },

    #[error("Proxy session error: {message}")]
    Session { message: String },

    #[error("Proxy code error: {message}")]
    Code { message: String },

    #[error("Proxy operation failed: {operation}")]
    Operation { operation: String },

    // SAML compatibility variant
    #[error("Invalid SAML redirect URL")]
    InvalidSAMLRedirectUrl,
}

impl ProxyError {
    /// Create an authentication error with a custom message
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a session error with a custom message
    pub fn session(message: impl Into<String>) -> Self {
        Self::Session {
            message: message.into(),
        }
    }

    /// Create a code error with a custom message
    pub fn code(message: impl Into<String>) -> Self {
        Self::Code {
            message: message.into(),
        }
    }

    /// Create an operation error with a custom message
    pub fn operation(operation: impl Into<String>) -> Self {
        Self::Operation {
            operation: operation.into(),
        }
    }
}
