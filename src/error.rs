use std::collections::BTreeMap;
use std::string::FromUtf8Error;

use actix_web::http::header::{self, ContentType};
use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use derive_more::{Display, Error as DeriveError};
use reqwest::header::ToStrError;

use crate::secret::{BrowserSessionSecret, WebAuthnAuthSecret, WebAuthnRegSecret};
use crate::utils::get_partial;

pub type Response = std::result::Result<HttpResponse, Error>;
pub type Result<T> = std::result::Result<T, Error>;

pub async fn not_found() -> Response {
	Err(AppErrorKind::NotFound.into())
}

#[derive(Debug, Display, DeriveError, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppErrorKind {
	// Authentication & secret errors
	#[display("The provided secret is bound to a token that no longer exists")]
	NoParentToken,
	NoSessionSet,
	MissingMetadata,
	IncorrectMetadata,
	InvalidTargetUser,
	InvalidParentToken,
	#[display("The provided secret is of the wrong type")]
	InvalidSecretType,
	#[display("The provided secret has expired")]
	ExpiredSecret,
	#[display("The metadata provided to the secret were invalid")]
	InvalidSecretMetadata,
	#[display("The request does not have a valid magic link token")]
	MissingLoginLinkCode,
	Unauthorized,

	// Database errors
	#[display("Unable to access the database instance during request parsing")]
	DatabaseInstanceError,

	// Proxy (auth-url) errors
	#[display("Missing auth_url code in (query string or cookie)")]
	MissingAuthURLCode,
	#[display("Could not parse X-Original-URI header (it is set but not valid)")]
	CouldNotParseXOriginalURIHeader,
	#[display("The provided return destination URL (`rd` query parameter) doesn't have a an origin that is allowed in the config")]
	InvalidReturnDestinationUrl,
	InvalidOriginHeader,

	// Generic errors
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
	MissingOriginHeader,
	NoLoginLinkRedirect,
	#[display("Multiple login link redirect query parameters were given (rd, saml, oidc)")]
	MultipleLoginLinkRedirectDefinitions,

	// OIDC errors
	#[display("OIDC Client sent a redirect_uri different from the one in the config")]
	InvalidOIDCRedirectUrl,
	#[display("OIDC Client did not send a redirect_uri")]
	MissingOIDCRedirectUrl,
	#[display("The OIDC client_id shown during authorization does not match the client_id provided")]
	NotMatchingClientID,
	#[display("OIDC Client sent a client_id that is not in the config")]
	InvalidClientID,
	#[display("OIDC Client sent a client_secret that does not correspond to the client_id it sent")]
	InvalidClientSecret,
	#[display("OIDC not configured for this client")]
	OIDCNotConfigured,
	#[display("OIDC Client did not send a client_id")]
	NoClientID,
	#[display("OIDC Client did not send a client_secret")]
	NoClientSecret,
	#[display("OIDC Client did not send a client_secret or a code_challenge")]
	NoClientSecretOrCodeChallenge,
	#[display("OIDC Client sent a code_challenge_method that is not S256")]
	InvalidCodeChallengeMethod,
	#[display("OIDC Client sent a code_verifier but did not send a code_challenge")]
	NoCodeChallenge,
	#[display("Someone tried to get a token with an invalid invalid OIDC code")]
	InvalidOIDCCode,
	#[display("The OIDC code_verifier does not match the code_challenge")]
	InvalidCodeVerifier,
	#[display("The client tried to create a token without providing any credentials (client_verifier or client_secret)")]
	NoClientCredentialsProvided,

	// SAML errors
	#[display("SAML Client sent a redirect_uri different from the one in the config")]
	InvalidSAMLRedirectUrl,

	// WebAuthn errors
	PasskeyAlreadyRegistered,
	#[display("The provided webauthn secret does not exist")]
	WebAuthnSecretNotFound,

	// Kubernetes errors
	#[display("Kubernetes ingress has no host")]
	IngressHasNoHost,
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
				AppErrorKind::NotLoggedIn
				| AppErrorKind::ExpiredSecret
				| AppErrorKind::WebAuthnSecretNotFound => StatusCode::FOUND,
				AppErrorKind::Unauthorized
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

		#[cfg(any(debug_assertions, test))]
		println!("Error: {}", self);

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

		if self.app_error == Some(AppErrorKind::WebAuthnSecretNotFound)
			|| self.app_error == Some(AppErrorKind::NotLoggedIn)
		{
			HttpResponse::build(status)
				.cookie(BrowserSessionSecret::unset_cookie())
				.cookie(WebAuthnRegSecret::unset_cookie())
				.cookie(WebAuthnAuthSecret::unset_cookie())
				.append_header((header::LOCATION, "/login"))
				.finish()
		} else {
			let status_code = self.status_code().as_u16().to_string();
			let error_name = self.status_code().canonical_reason().unwrap_or_default();

			let mut page_data = BTreeMap::new();
			page_data.insert("code", status_code.clone());
			page_data.insert("error", error_name.to_string());
			page_data.insert("description", description.clone());

			let page = get_partial::<()>("error", page_data, None).unwrap_or_else(|_| {
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

macro_rules! from_error {
	($struct:path, $format:literal) => {
		impl From<$struct> for Error {
			fn from(error: $struct) -> Self {
				format!($format, error).into()
			}
		}
	};
}

from_error!(FromUtf8Error, "UTF-8 Decoding error: {}");
from_error!(ToStrError, "ToStr error: {}");

from_error!(actix_web::cookie::ParseError, "Actix Cookie error: {}");
from_error!(actix_web::http::uri::InvalidUri, "Actix Invalid URI error: {}");
from_error!(actix_web::http::header::ToStrError, "Actix Header value to string error: {}");

from_error!(base64::DecodeError, "Base64 decode error: {}");
from_error!(formatx::Error, "Formatx formatting error: {}");
from_error!(handlebars::RenderError, "Handlebars render error: {}");
from_error!(jwt_simple::Error, "JWT Simple error: {}");
from_error!(jwt_simple::reexports::ct_codecs::Error, "JWT Simple CT Codecs error: {}");
from_error!(lettre::error::Error, "Lettre error: {}");
from_error!(lettre::transport::stub::Error, "Lettre (Stub transport) error: {}");
from_error!(lettre::transport::smtp::Error, "Lettre (SMTP transport) error: {}");
from_error!(lettre::address::AddressError, "Lettre Address error: {}");
from_error!(quick_xml::DeError, "Quick XML deserialization error: {}");
from_error!(quick_xml::SeError, "Quick XML serialization error: {}");
from_error!(reindeer::Error, "Reindeer database error: {}");
from_error!(reqwest::Error, "Reqwest error: {}");
from_error!(rsa::pkcs1::Error, "RSA PKCS1 error: {}");
from_error!(url::ParseError, "URL Parse Error: {}");
from_error!(webauthn_rs::prelude::WebauthnError, "WebAuthN error: {}");

from_error!(std::io::Error, "IO error: {}");
from_error!(tokio::sync::TryLockError, "Tokio Mutex lock error: {}");

from_error!(serde_json::Error, "Serde-JSON error: {}");
from_error!(serde_qs::Error, "Serde-QS error: {}");
from_error!(serde_yaml::Error, "Serde-YAML error: {}");

#[cfg(feature = "kube")]
from_error!(kube::Error, "Kube error: {}");
#[cfg(feature = "kube")]
from_error!(kube::runtime::watcher::Error, "Kube watcher error: {}");
