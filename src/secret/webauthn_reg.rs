use actix_web::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::webauthn::WEBAUTHN_REG_COOKIE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnRegSecretKind;

impl UserSecretKind for WebAuthnRegSecretKind {
	const PREFIX: &'static str = "webauthn_reg";
	type Metadata = webauthn_rs::prelude::PasskeyRegistration;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type WebAuthnRegSecret = EphemeralUserSecret<WebAuthnRegSecretKind, BrowserSessionSecretKind>;

impl actix_web::FromRequest for WebAuthnRegSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.cookie(WEBAUTHN_REG_COOKIE) else {
			return Box::pin(async { Err(AppErrorKind::WebAuthnSecretNotFound.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
		})
	}
}

impl From<WebAuthnRegSecret> for Cookie<'_> {
	fn from(val: WebAuthnRegSecret) -> Cookie<'static> {
		Cookie::build(
			WEBAUTHN_REG_COOKIE,
			val.code().to_str_that_i_wont_print().to_owned(),
		)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish()
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
