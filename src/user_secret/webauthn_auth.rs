use actix_web::cookie::Cookie;
use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::webauthn::WEBAUTHN_COOKIE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;

#[derive(PartialEq, Serialize, Deserialize)]
pub struct WebAuthnAuthSecretKind;

impl UserSecretKind for WebAuthnAuthSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = webauthn_rs::prelude::PasskeyAuthentication;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type WebAuthnAuthSecret = EphemeralUserSecret<WebAuthnAuthSecretKind, BrowserSessionSecretKind>;

impl actix_web::FromRequest for WebAuthnAuthSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.match_info().get(WEBAUTHN_COOKIE) else {
			return Box::pin(async { Err(AppErrorKind::MissingLoginLinkCode.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<Db>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		let code = code.to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
		})
	}
}

impl Into<Cookie<'_>> for WebAuthnAuthSecret {
	fn into(self) -> Cookie<'static> {
		// TODO: Unset the cookie on error
		Cookie::new(
			WEBAUTHN_COOKIE,
			self.code().to_str_that_i_wont_print().to_owned(),
		)
	}
}
