//! `WebAuthn` authentication errors

use thiserror::Error;

/// WebAuthn-related errors
#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("Passkey already registered")]
    AlreadyRegistered,

    #[error("The provided webauthn secret does not exist")]
    SecretNotFound,

    #[error("WebAuthn protocol error: {message}")]
    Protocol { message: String },

    #[error("WebAuthn authentication error: {message}")]
    Authentication { message: String },

    #[error("WebAuthn registration error: {message}")]
    Registration { message: String },

    #[error("Invalid WebAuthn challenge")]
    InvalidChallenge,

    #[error("WebAuthn credential validation failed")]
    ValidationFailed,

    #[error("WebAuthn operation failed: {operation}")]
    Operation { operation: String },
}

impl WebAuthnError {
    /// Create a protocol error with a custom message
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }

    /// Create an authentication error with a custom message
    pub fn authentication(message: impl Into<String>) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    /// Create a registration error with a custom message
    pub fn registration(message: impl Into<String>) -> Self {
        Self::Registration {
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
