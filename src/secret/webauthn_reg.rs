use actix_web::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{DatabaseError, WebAuthnError};
use crate::webauthn::WEBAUTHN_REG_COOKIE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;
use super::SecretType;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegSecretKind;

impl UserSecretKind for WebAuthnRegSecretKind {
	const PREFIX: SecretType = SecretType::WebAuthnReg;
	type Metadata = webauthn_rs::prelude::PasskeyRegistration;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type WebAuthnRegSecret = EphemeralUserSecret<WebAuthnRegSecretKind, BrowserSessionSecretKind>;

impl actix_web::FromRequest for WebAuthnRegSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.cookie(WEBAUTHN_REG_COOKIE) else {
			return Box::pin(async { Err(WebAuthnError::SecretNotFound.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(DatabaseError::InstanceError.into()) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
				.map_err(Into::into)
		})
	}
}

impl From<WebAuthnRegSecret> for Cookie<'_> {
	fn from(val: WebAuthnRegSecret) -> Cookie<'static> {
		Cookie::build(
			WEBAUTHN_REG_COOKIE,
			val.code().to_str_that_i_wont_print(),
		)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish()
	}
}

impl From<&WebAuthnRegSecret> for axum_extra::extract::cookie::Cookie<'_> {
	fn from(val: &WebAuthnRegSecret) -> axum_extra::extract::cookie::Cookie<'static> {
		axum_extra::extract::cookie::Cookie::build((
			WEBAUTHN_REG_COOKIE,
			val.code().to_str_that_i_wont_print(),
		))
		.http_only(true)
		.path("/")
		.build()
	}
}

use axum::RequestPartsExt;

impl axum::extract::FromRequestParts<crate::AppState> for WebAuthnRegSecret {
	type Rejection = crate::error::AppError;

	async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &crate::AppState) -> Result<Self, Self::Rejection> {
		let Ok(jar) = parts.extract::<axum_extra::extract::CookieJar>().await;

		let Some(cookie) = jar.get(WEBAUTHN_REG_COOKIE) else {
			return Err(WebAuthnError::SecretNotFound.into());
		};


		Ok(Self::try_from_string(cookie.value().to_string(), &state.db).await?)
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
