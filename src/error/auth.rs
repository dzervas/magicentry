//! Authentication and secret management errors

use thiserror::Error;

/// Authentication and secret-related errors
#[derive(Debug, Clone, Error)]
pub enum AuthError {
    // Authentication & secret errors
    #[error("The provided secret is bound to a token that no longer exists")]
    NoParentToken,

    #[error("No session set")]
    NoSessionSet,

    #[error("Missing metadata")]
    MissingMetadata,

    #[error("Incorrect metadata")]
    IncorrectMetadata,

    #[error("Invalid target user")]
    InvalidTargetUser,

    #[error("Invalid parent token")]
    InvalidParentToken,

    #[error("The provided secret is of the wrong type")]
    InvalidSecretType,

    #[error("The provided secret has expired")]
    ExpiredSecret,

    #[error("The provided secret does not exist")]
    InvalidSecret,

    #[error("The metadata provided to the secret were invalid")]
    InvalidSecretMetadata,

    #[error("The request does not have a valid magic link token")]
    MissingLoginLinkCode,

    #[error("Unauthorized")]
    Unauthorized,

    // Generic errors
    #[error("What you're looking for ain't here")]
    NotFound,

    #[error("You are not logged in!")]
    NotLoggedIn,

    #[error("Missing Authorization header")]
    MissingAuthorizationHeader,

    #[error("The provided Authorization header is invalid")]
    InvalidAuthorizationHeader,

    #[error("Could not parse Authorization header")]
    CouldNotParseAuthorizationHeader,

    #[error("The Duration provided is incorrect or too big (max i64)")]
    InvalidDuration,

    #[error("Missing origin header")]
    MissingOriginHeader,

    #[error("No login link redirect")]
    NoLoginLinkRedirect,

    #[error("Multiple login link redirect query parameters were given (rd, saml, oidc)")]
    MultipleLoginLinkRedirectDefinitions,

    // OIDC-specific errors (for compatibility)
    #[error("Invalid OIDC code")]
    InvalidOIDCCode,

    #[error("Invalid client ID")]
    InvalidClientID,

    #[error("Invalid client secret")]
    InvalidClientSecret,

    #[error("The provided secret is not valid")]
    SecretValidation { message: String },

    #[error("Secret operation failed: {operation}")]
    SecretOperation { operation: String },

    #[error("Kubernetes ingress has no host")]
    IngressHasNoHost,
}

impl AuthError {
    /// Create a secret validation error with a custom message
    pub fn secret_validation(message: impl Into<String>) -> Self {
        Self::SecretValidation {
            message: message.into(),
        }
    }

    /// Create a secret operation error with a custom message
    pub fn secret_operation(operation: impl Into<String>) -> Self {
        Self::SecretOperation {
            operation: operation.into(),
        }
    }
}
