//! Error handling module with domain-specific error types
//!
//! This module provides a modular error handling approach using anyhow and thiserror.
//! Each domain has its own error type, and they're all unified under the core [`AppError`].

use actix_web::http::header::{self, ContentType};
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use thiserror::Error;

use crate::pages::Page as _;

pub use self::database::DatabaseError;
pub use self::auth::AuthError;
pub use self::oidc::OidcError;
pub use self::webauthn::WebAuthnError;
pub use self::proxy::ProxyError;
pub use self::pages::PageError;

#[allow(clippy::unused_async)]
pub async fn not_found() -> Response {
	Err(AuthError::NotFound.into())
}

mod database;
mod auth;
mod oidc;
mod webauthn;
mod proxy;
mod pages;

/// HTTP response result type used by handlers
pub type Response = std::result::Result<HttpResponse, AppError>;

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

impl ResponseError for AppError {
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

	/// Create an error response for HTTP handlers
	fn error_response(&self) -> HttpResponse {
		let status = self.status_code();
		#[cfg(not(debug_assertions))]
		let mut description = self.to_string();

		if status.is_server_error() {
			tracing::error!("{self}");

			#[cfg(not(debug_assertions))]
			{
				description.clear();
				description = "Something went very wrong from our end".to_string();
			}
		} else if status != StatusCode::NOT_FOUND {
			tracing::warn!("{self}");
		}

		if status == StatusCode::FOUND {
			use crate::secret::{BrowserSessionSecret, WebAuthnAuthSecret, WebAuthnRegSecret};
			HttpResponse::build(status)
				.cookie(BrowserSessionSecret::unset_cookie())
				.cookie(WebAuthnRegSecret::unset_cookie())
				.cookie(WebAuthnAuthSecret::unset_cookie())
				.append_header((header::LOCATION, "/login"))
				.finish()
		} else {
			// let status_code = status.as_u16().to_string();
			// let error_name = status.canonical_reason().unwrap_or_default();
			// let page = crate::pages::ErrorPage {
			//     code: status_code,
			//     error: error_name.to_string(),
			//     description,
			// };
			// let rendered = {
			//     use tokio::runtime::Handle;
			//     let handle = Handle::current();
			//     handle.block_on(page.render())
			// };
			// TODO: there needs to be a middleware after the response generation that handles errors and generates the page
			let rendered = format!(
				r#"<!DOCTYPE html>
					<html lang="en">
					<head>
						<meta charset="UTF-8">
						<meta http-equiv="X-UA-Compatible" content="IE=edge">
						<meta name="viewport" content="width=device-width, initial-scale=1.0">
						<title>Magic Entry</title>
						<link rel="stylesheet" href="/static/style.css">
					</head>
					<body>
						<h1>{status_code} {error_name}</h1>
						<p>{description}</p>
					</body>
					</html>
				"#,
				status_code = status.as_str(),
				error_name = status.canonical_reason().unwrap_or("Unknown"),
				description = status.canonical_reason().unwrap_or("Unknown")
			);

			HttpResponse::build(status)
				.content_type(ContentType::html())
				.body(rendered)
		}
	}
}

impl axum::response::IntoResponse for AppError {
	fn into_response(self) -> axum::response::Response {
		let status_num = self.status_code().as_u16();
		let status = axum::http::StatusCode::from_u16(status_num).unwrap();
		let body = format!("Error {}: {}", status.as_u16(), self);

		(status, axum::response::Html(body)).into_response()
	}
}

impl AppError {
	pub fn render_with_state(&self, state: &crate::AppState) -> impl axum::response::IntoResponse {
		let config = &state.config;
		let status_num = self.status_code().as_u16();
		let status = axum::http::StatusCode::from_u16(status_num).unwrap();

		let error = crate::pages::error::ErrorPage {
			code: status_num.to_string(),
			error: self.to_string(),
			description: self.to_string(),
		};

		let body = error.render_with_config(config);

		(status, body)
	}
  }

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

use axum::response::IntoResponse;
// #[axum::debug_handler]
pub async fn error_handler(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	response: axum::response::Response,
) -> impl axum::response::IntoResponse {
    // let (parts, body) = response.into_parts();

    // let status_num = parts.status.as_u16();
    // if status_num < 400 {
    //     // We only care about client or server errors
    //     return axum::response::Response::from_parts(parts, body);
    // }

	// Check if response is an error and handle it
	match response.extensions().get::<AppError>() {
		Some(error) => error.render_with_state(&state).into_response(),
		None => response,
	}
}
