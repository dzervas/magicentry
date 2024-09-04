use std::collections::BTreeMap;
use std::string::FromUtf8Error;

use actix_web::http::header::{self, ContentType};
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use derive_more::{Display, Error as DeriveError};
use reqwest::header::ToStrError;

use crate::utils::get_partial;

pub type Response = std::result::Result<HttpResponse, Error>;
pub type Result<T> = std::result::Result<T, Error>;

pub async fn not_found() -> Response {
	Err(AppErrorKind::NotFound.into())
}

#[derive(Debug, Display, DeriveError, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppErrorKind {
	TokenNotFound,
	NoParentToken,
	NoSessionSet,
	MissingMetadata,
	IncorrectMetadata,
	InvalidTargetUser,
	MissingCookieHeader,
	MissingOriginHeader,
	InvalidParentToken,

	#[display("What you're looking for ain't here")]
	NotFound,
	#[display("You are not logged in!")]
	NotLoggedIn,
	#[display("Missing Authorization header")]
	MissingAuthorizationHeader,
	#[display("The provided Authorization header is invalid")]
	InvalidAuthorizationHeader,
	#[display("Could not parse Authorization header")]
	CouldNotParseAuthorizationHeader,
	#[display("The Duration provided is incorrect or too big (max i64)")]
	InvalidDuration,
	#[display("Client sent a redirect_uri different from the one in the config")]
	InvalidRedirectUri,
	#[display("The client_id shown during authorization does not match the client_id provided")]
	NotMatchingClientID,
	#[display("Client sent a client_id that is not in the config")]
	InvalidClientID,
	#[display("Client sent a client_secret that does not correspond to the client_id it sent")]
	InvalidClientSecret,
	#[display("Client did not send a client_id")]
	NoClientID,
	#[display("Client did not send a client_secret")]
	NoClientSecret,
	#[display("Client did not send a client_secret or a code_challenge")]
	NoClientSecretOrCodeChallenge,
	#[display("Client sent a code_challenge_method that is not S256")]
	InvalidCodeChallengeMethod,
	#[display("Client sent a code_verifier but did not send a code_challenge")]
	NoCodeChallenge,
	#[display("Someone tried to get a token with an invalid invalid OIDC code")]
	InvalidOIDCCode,
	#[display("The code_verifier does not match the code_challenge")]
	InvalidCodeVerifier,
	#[display(
		"The client tried to create a token without providing any credentials (client_verifier or client_secret)"
	)]
	NoClientCredentialsProvided,
	PasskeyAlreadyRegistered,
}

#[derive(Debug, Display, DeriveError, Clone)]
#[display("Internal Server Error: {}", cause)]
pub struct Error {
	cause: String,
	app_error: Option<AppErrorKind>,
}

impl ResponseError for Error {
	fn status_code(&self) -> StatusCode {
		if let Some(app_error) = &self.app_error {
			match app_error {
				AppErrorKind::TokenNotFound => StatusCode::FOUND,
				AppErrorKind::NotLoggedIn
				| AppErrorKind::InvalidOIDCCode
				| AppErrorKind::InvalidClientID
				| AppErrorKind::InvalidClientSecret => StatusCode::UNAUTHORIZED,
				AppErrorKind::NotFound => StatusCode::NOT_FOUND,
				AppErrorKind::InvalidTargetUser | AppErrorKind::InvalidParentToken => {
					StatusCode::INTERNAL_SERVER_ERROR
				}

				_ => StatusCode::BAD_REQUEST,
			}
		} else {
			StatusCode::INTERNAL_SERVER_ERROR
		}
	}

	fn error_response(&self) -> HttpResponse {
		let status = self.status_code();
		#[allow(unused_mut)] // Since it's used during release builds
		let mut description = self.cause.clone();

		if status.is_server_error() {
			log::error!("{}", self);

			#[cfg(not(debug_assertions))]
			{
				description.clear();
				description = "Something went very wrong from our end".to_string();
			}
		} else if status != StatusCode::NOT_FOUND {
			log::warn!("{}", self);
		}

		if self.app_error == Some(AppErrorKind::TokenNotFound)
			|| self.app_error == Some(AppErrorKind::NotLoggedIn)
		{
			HttpResponse::build(status)
				.append_header((header::LOCATION, "/login"))
				.finish()
		} else {
			let status_code = self.status_code().as_u16().to_string();
			let error_name = self.status_code().canonical_reason().unwrap_or_default();

			let mut page_data = BTreeMap::new();
			page_data.insert("code", status_code.clone());
			page_data.insert("error", error_name.to_string());
			page_data.insert("description", description.clone());

			let page = get_partial("error", page_data).unwrap_or_else(|_| {
				log::error!("Could not format error page");
				"Internal server error".to_string()
			});

			HttpResponse::build(status)
				.content_type(ContentType::html())
				.body(page)
		}
	}
}

impl From<String> for Error {
	fn from(error: String) -> Self {
		Self {
			cause: error,
			app_error: None,
		}
	}
}

impl From<AppErrorKind> for Error {
	fn from(error: AppErrorKind) -> Self {
		Self {
			cause: format!("{}", error),
			app_error: Some(error),
		}
	}
}

impl From<ToStrError> for Error {
	fn from(error: ToStrError) -> Self {
		format!("ToStr error: {}", error).into()
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Self {
		format!("ToStr error: {}", error).into()
	}
}

impl From<actix_web::cookie::ParseError> for Error {
	fn from(error: actix_web::cookie::ParseError) -> Self {
		format!("Actix Cookie error: {}", error).into()
	}
}

impl From<actix_web::http::uri::InvalidUri> for Error {
	fn from(error: actix_web::http::uri::InvalidUri) -> Self {
		format!("Actix Invalid URI error: {}", error).into()
	}
}

impl From<actix_session::SessionGetError> for Error {
	fn from(error: actix_session::SessionGetError) -> Self {
		format!("Session Get error: {}", error).into()
	}
}

impl From<actix_session::SessionInsertError> for Error {
	fn from(error: actix_session::SessionInsertError) -> Self {
		format!("Session Insert error: {}", error).into()
	}
}

impl From<reindeer::Error> for Error {
	fn from(error: reindeer::Error) -> Self {
		format!("Database error: {}", error).into()
	}
}

impl From<FromUtf8Error> for Error {
	fn from(error: FromUtf8Error) -> Self {
		format!("Decoding error: {}", error).into()
	}
}

impl From<formatx::Error> for Error {
	fn from(error: formatx::Error) -> Self {
		format!("Formatting error: {}", error).into()
	}
}

impl From<lettre::error::Error> for Error {
	fn from(error: lettre::error::Error) -> Self {
		format!("Lettre error: {}", error).into()
	}
}

impl From<lettre::transport::stub::Error> for Error {
	fn from(error: lettre::transport::stub::Error) -> Self {
		format!("Lettre (Stub transport) error: {}", error).into()
	}
}

impl From<lettre::transport::smtp::Error> for Error {
	fn from(error: lettre::transport::smtp::Error) -> Self {
		format!("Lettre (SMTP transport) error: {}", error).into()
	}
}

impl From<lettre::address::AddressError> for Error {
	fn from(error: lettre::address::AddressError) -> Self {
		format!("Lettre Address error: {}", error).into()
	}
}

impl From<reqwest::Error> for Error {
	fn from(error: reqwest::Error) -> Self {
		format!("Reqwest error: {}", error).into()
	}
}

impl From<serde_qs::Error> for Error {
	fn from(error: serde_qs::Error) -> Self {
		format!("Serde-qs error: {}", error).into()
	}
}

impl From<serde_json::Error> for Error {
	fn from(error: serde_json::Error) -> Self {
		format!("Serde-JSON error: {}", error).into()
	}
}

impl From<serde_yaml::Error> for Error {
	fn from(error: serde_yaml::Error) -> Self {
		format!("Serde-YAML error: {}", error).into()
	}
}

impl From<jwt_simple::Error> for Error {
	fn from(error: jwt_simple::Error) -> Self {
		format!("JWT Simple error: {}", error).into()
	}
}

impl From<jwt_simple::reexports::ct_codecs::Error> for Error {
	fn from(error: jwt_simple::reexports::ct_codecs::Error) -> Self {
		format!("CT Codecs error: {}", error).into()
	}
}

impl From<webauthn_rs::prelude::WebauthnError> for Error {
	fn from(error: webauthn_rs::prelude::WebauthnError) -> Self {
		format!("WebAuthN error: {}", error).into()
	}
}

impl From<handlebars::RenderError> for Error {
	fn from(error: handlebars::RenderError) -> Self {
		format!("Handlebars render error: {}", error).into()
	}
}

impl From<tokio::sync::TryLockError> for Error {
	fn from(error: tokio::sync::TryLockError) -> Self {
		format!("Mutex lock error: {}", error).into()
	}
}

#[cfg(feature = "kube")]
impl From<kube::Error> for Error {
	fn from(error: kube::Error) -> Self {
		format!("Kube error: {}", error).into()
	}
}

#[cfg(feature = "kube")]
impl From<kube::runtime::watcher::Error> for Error {
	fn from(error: kube::runtime::watcher::Error) -> Self {
		format!("Kube error: {}", error).into()
	}
}
