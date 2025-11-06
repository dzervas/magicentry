//! Error handling module with domain-specific error types
//!
//! This module provides a modular error handling approach using anyhow and thiserror.
//! Each domain has its own error type, and they're all unified under the core [`AppError`].

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;
use tracing::{error, warn};

pub use self::database::DatabaseError;
pub use self::auth::AuthError;
pub use self::oidc::OidcError;
pub use self::webauthn::WebAuthnError;
pub use self::proxy::ProxyError;
pub use self::pages::PageError;

use crate::pages::ErrorPage;
use crate::{
    SESSION_COOKIE,
    PROXY_SESSION_COOKIE,
    AUTHORIZATION_COOKIE,
    webauthn::{WEBAUTHN_AUTH_COOKIE, WEBAUTHN_REG_COOKIE},
};

mod database;
mod auth;
mod oidc;
mod webauthn;
mod proxy;
mod pages;

/// Create cookie removal headers for all authentication cookies
fn create_cookie_removal_headers() -> Vec<String> {
    let auth_cookies = [
        SESSION_COOKIE,
        PROXY_SESSION_COOKIE,
        AUTHORIZATION_COOKIE,
        WEBAUTHN_AUTH_COOKIE,
        WEBAUTHN_REG_COOKIE,
    ];

    auth_cookies
        .iter()
        .map(|&name| {
            // Create a removal cookie with empty value and expiration in the past
            format!("{}=; Max-Age=0", name)
        })
        .collect()
}

/// Core application error that unifies all domain errors
#[derive(Debug, Error)]
pub enum AppError {
	#[error("Database error: {0}")]
	Database(#[from] DatabaseError),

	#[error("Authentication error: {0}")]
	Auth(#[from] AuthError),

	#[error("OIDC error: {0}")]
	Oidc(#[from] OidcError),

	#[error("WebAuthn error: {0}")]
	WebAuthn(#[from] WebAuthnError),

	#[error("Proxy error: {0}")]
	Proxy(#[from] ProxyError),

	#[error("Page rendering error: {0}")]
	Page(#[from] PageError),

	#[error("Config error: {0}")]
	Config(&'static str),

	#[error("Internal error: {0}")]
	Internal(#[from] anyhow::Error),
}

impl AppError {
	/// Get the HTTP status code for this error
	fn status_code(&self) -> StatusCode {
		match self {
			Self::Database(
				DatabaseError::Connection { .. }
				| DatabaseError::Migration { .. }
				| DatabaseError::Query { .. }
			) | Self::Auth(
				AuthError::InvalidTargetUser
				| AuthError::InvalidParentToken
			) => StatusCode::INTERNAL_SERVER_ERROR,

			Self::Auth(AuthError::NotLoggedIn
				| AuthError::ExpiredSecret
				| AuthError::InvalidSecret
				| AuthError::InvalidSecretType
				| AuthError::InvalidSecretMetadata
				| AuthError::MissingLoginLinkCode
			)
			| Self::WebAuthn(WebAuthnError::SecretNotFound) => StatusCode::FOUND,

			Self::Auth(
				AuthError::Unauthorized
				| AuthError::InvalidClientSecret
				| AuthError::InvalidOIDCCode
				| AuthError::InvalidClientID
			) => StatusCode::UNAUTHORIZED,

			Self::Auth(AuthError::NotFound) => StatusCode::NOT_FOUND,

			_ => StatusCode::BAD_REQUEST,
		}
	}
}

impl IntoResponse for AppError {
	fn into_response(self) -> Response {
		let status = self.status_code();

		if status.is_server_error() {
			error!("Internal Server error: {self}");
		} else if status != StatusCode::NOT_FOUND {
			warn!("Client error: {self}");
		}

		if status != StatusCode::FOUND {
			// TODO: Correct description
			return (status, ErrorPage::render_sync(status.as_u16(), self.to_string(), self.to_string())).into_response();
		}

		let mut response = status.into_response();

		let headers = response.headers_mut();
		headers.append("Location", "/login".parse().unwrap());

		// Add cookie removal headers to clean up invalid authentication
		if matches!(self, Self::Auth(AuthError::NotLoggedIn | AuthError::ExpiredSecret | AuthError::InvalidSecret)) {
			for cookie_header in create_cookie_removal_headers() {
				if let Ok(header_value) = cookie_header.parse() {
					headers.append("Set-Cookie", header_value);
				}
			}
		}

		response
	}
}

// impl AppError {
// 	pub fn render_with_state(&self, config: &LiveConfig) -> impl IntoResponse {
// 		let status_num = self.status_code().as_u16();
// 		let status = StatusCode::from_u16(status_num).unwrap();
//
// 		let error = ErrorPage {
// 			code: status_num.to_string(),
// 			error: self.to_string(),
// 			description: self.to_string(),
// 		};
//
// 		let body = error.render_with_config(config);
//
// 		(status, body)
// 	}
//   }

// Legacy compatibility - allow conversion from string
impl From<String> for AppError {
	fn from(error: String) -> Self {
		Self::Internal(anyhow::anyhow!(error))
	}
}

impl From<&'static str> for AppError {
	fn from(error: &'static str) -> Self {
		Self::Internal(anyhow::anyhow!(error))
	}
}
//
// pub async fn error_handler(
// 	State(_state): State<AppState>,
// 	response: Response,
// ) -> impl IntoResponse {
// 	let Some(error) = response.extensions().get::<AppError>().cloned() else {
// 		return response;
// 	};
//
// 	let (parts, _body) = response.into_parts();
// 	let status_num = parts.status.as_u16();
// 	if status_num < 400 {
// 		return response;
// 	}
//
// 	let error_page = ErrorPage::render_sync(status_num, error.to_string(), error.to_string());
//
// 	error_page
// }
