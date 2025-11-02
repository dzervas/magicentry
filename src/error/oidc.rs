//! `OpenID` Connect protocol errors

use thiserror::Error;

/// OIDC protocol-related errors
#[derive(Debug, Clone, Error)]
pub enum OidcError {
    #[error("OIDC Client sent a redirect_uri different from the one in the config")]
    InvalidRedirectUrl,

    #[error("OIDC Client did not send a redirect_uri")]
    MissingRedirectUrl,

    #[error("The OIDC client_id shown during authorization does not match the client_id provided")]
    NotMatchingClientID,

    #[error("OIDC Client sent a client_id that is not in the config")]
    InvalidClientID,

    #[error("OIDC Client sent a client_secret that does not correspond to the client_id it sent")]
    InvalidClientSecret,

    #[error("OIDC not configured for this client")]
    NotConfigured,

    #[error("OIDC Client did not send a client_id")]
    NoClientID,

    #[error("OIDC Client did not send a client_secret")]
    NoClientSecret,

    #[error("OIDC Client did not send a client_secret or a code_challenge")]
    NoClientSecretOrCodeChallenge,

    #[error("OIDC Client sent a code_challenge_method that is not S256")]
    InvalidCodeChallengeMethod,

    #[error("OIDC Client sent a code_verifier but did not send a code_challenge")]
    NoCodeChallenge,

    #[error("Someone tried to get a token with an invalid invalid OIDC code")]
    InvalidCode,

    #[error("The OIDC code_verifier does not match the code_challenge")]
    InvalidCodeVerifier,

    #[error("The client tried to create a token without providing any credentials (client_verifier or client_secret)")]
    NoClientCredentialsProvided,

    #[error("OIDC protocol error: {message}")]
    Protocol { message: String },

    #[error("OIDC token error: {message}")]
    Token { message: String },

    #[error("OIDC authorization error: {message}")]
    Authorization { message: String },
}

impl OidcError {
    /// Create a protocol error with a custom message
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }

    /// Create a token error with a custom message
    pub fn token(message: impl Into<String>) -> Self {
        Self::Token {
            message: message.into(),
        }
    }

    /// Create an authorization error with a custom message
    pub fn authorization(message: impl Into<String>) -> Self {
        Self::Authorization {
            message: message.into(),
        }
    }
}
