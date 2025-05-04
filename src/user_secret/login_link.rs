use futures::future::BoxFuture;
use reindeer::Db;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_secret::EphemeralUserSecret;
use super::secret::UserSecretKind;

use crate::error::{AppErrorKind, Result};

pub struct LoginLinkSecretKind;

impl UserSecretKind for LoginLinkSecretKind {
	const PREFIX: &'static str = "login";
	type Metadata = Option<url::Url>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.link_duration }
}

pub type LoginLinkSecret = EphemeralUserSecret<LoginLinkSecretKind, BrowserSessionSecretKind>;

impl LoginLinkSecret {
	pub fn get_login_url(&self) -> String {
		format!("/login/{}", self.code().to_str_that_i_wont_print())
	}
}

impl actix_web::FromRequest for LoginLinkSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let code = if let Some(code) = req.match_info().get("magic") {
			code.to_string()
		} else {
			return Box::pin(async { Err(AppErrorKind::MissingLoginLinkCode.into()) });
		};

		let db = if let Some(db) = req.app_data::<actix_web::web::Data<Db>>() {
			db.clone()
		} else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
		})
	}
}
