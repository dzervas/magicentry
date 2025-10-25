use actix_web::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{DatabaseError, WebAuthnError};
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

impl actix_web::FromRequest for WebAuthnAuthSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.cookie(WEBAUTHN_AUTH_COOKIE) else {
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

impl From<WebAuthnAuthSecret> for Cookie<'_> {
	fn from(val: WebAuthnAuthSecret) -> Cookie<'static> {
		Cookie::build(
			WEBAUTHN_AUTH_COOKIE,
			val.code().to_str_that_i_wont_print(),
		)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish()
	}
}

impl WebAuthnAuthSecret {
	#[must_use]
	pub fn unset_cookie() -> Cookie<'static> {
		let mut cookie: Cookie<'_> = Cookie::new(WEBAUTHN_AUTH_COOKIE, "");
		cookie.make_removal();
		cookie
	}
}
