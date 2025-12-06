use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::config::LiveConfig;
use crate::error::{AppError, WebAuthnError};
use crate::webauthn::WEBAUTHN_REG_COOKIE;

use super::SecretType;
use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegSecretKind;

impl UserSecretKind for WebAuthnRegSecretKind {
	const PREFIX: SecretType = SecretType::WebAuthnReg;
	type Metadata = webauthn_rs::prelude::PasskeyRegistration;

	async fn duration(config: &LiveConfig) -> chrono::Duration {
		config.session_duration
	}
}

pub type WebAuthnRegSecret = EphemeralUserSecret<WebAuthnRegSecretKind, BrowserSessionSecretKind>;

impl From<&WebAuthnRegSecret> for Cookie<'_> {
	fn from(val: &WebAuthnRegSecret) -> Cookie<'static> {
		Cookie::build((WEBAUTHN_REG_COOKIE, val.code().to_str_that_i_wont_print()))
			.http_only(true)
			.path("/")
			.build()
	}
}

use axum::RequestPartsExt;

impl FromRequestParts<AppState> for WebAuthnRegSecret {
	type Rejection = AppError;

	async fn from_request_parts(
		parts: &mut Parts,
		state: &AppState,
	) -> Result<Self, Self::Rejection> {
		let Ok(jar) = parts.extract::<CookieJar>().await;

		let Some(cookie) = jar.get(WEBAUTHN_REG_COOKIE) else {
			return Err(WebAuthnError::SecretNotFound.into());
		};

		Self::try_from_string(cookie.value().to_string(), &state.db).await
	}
}

impl WebAuthnRegSecret {
	#[must_use]
	pub fn unset_cookie() -> Cookie<'static> {
		let mut cookie: Cookie<'_> = Cookie::new(WEBAUTHN_REG_COOKIE, "");
		cookie.make_removal();
		cookie
	}
}
