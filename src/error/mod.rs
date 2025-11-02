//! Error handling module with domain-specific error types
//!
//! This module provides a modular error handling approach using anyhow and thiserror.
//! Each domain has its own error type, and they're all unified under the core [`AppError`].

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;
use tracing::{error, warn};

pub use self::database::DatabaseError;
pub use self::auth::AuthError;
pub use self::oidc::OidcError;
pub use self::webauthn::WebAuthnError;
pub use self::proxy::ProxyError;
pub use self::pages::PageError;

mod database;
mod auth;
mod oidc;
mod webauthn;
mod proxy;
mod pages;

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
		eprintln!("Into response: {self}");
		let status = self.status_code();

		if status.is_server_error() {
			error!("Internal Server error: {self}");
		} else if status != StatusCode::NOT_FOUND {
			warn!("Client error: {self}");
		}

		if status == StatusCode::FOUND {
			eprintln!("Found");
			return (status, "/login").into_response();
		}

		let body = format!("Error {}: {}", status.as_u16(), self);

		(status, Html(body)).into_response()
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
