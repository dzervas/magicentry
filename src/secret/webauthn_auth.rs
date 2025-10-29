use axum::RequestPartsExt;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::WebAuthnError;
use crate::webauthn::WEBAUTHN_AUTH_COOKIE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;
use super::SecretType;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAuthSecretKind;

impl UserSecretKind for WebAuthnAuthSecretKind {
	const PREFIX: SecretType = SecretType::WebAuthnAuth;
	type Metadata = webauthn_rs::prelude::PasskeyAuthentication;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type WebAuthnAuthSecret = EphemeralUserSecret<WebAuthnAuthSecretKind, BrowserSessionSecretKind>;

impl From<&WebAuthnAuthSecret> for axum_extra::extract::cookie::Cookie<'_> {
	fn from(val: &WebAuthnAuthSecret) -> axum_extra::extract::cookie::Cookie<'static> {
		axum_extra::extract::cookie::Cookie::build((
			WEBAUTHN_AUTH_COOKIE,
			val.code().to_str_that_i_wont_print(),
		))
		.http_only(true)
		.path("/")
		.build()
	}
}

impl axum::extract::FromRequestParts<crate::AppState> for WebAuthnAuthSecret {
	type Rejection = crate::error::AppError;

	async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &crate::AppState) -> Result<Self, Self::Rejection> {
		let Ok(jar) = parts.extract::<axum_extra::extract::CookieJar>().await;

		let Some(cookie) = jar.get(WEBAUTHN_AUTH_COOKIE) else {
			return Err(WebAuthnError::SecretNotFound.into());
		};


		Ok(Self::try_from_string(cookie.value().to_string(), &state.db).await?)
	}
}
