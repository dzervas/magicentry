use actix_web::cookie::Cookie;
use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::SESSION_COOKIE;

use super::primitive::{UserSecret, UserSecretKind};
use super::metadata::EmptyMetadata;

#[derive(PartialEq, Serialize, Deserialize)]
pub struct BrowserSessionSecretKind;

impl UserSecretKind for BrowserSessionSecretKind {
	const PREFIX: &'static str = "session";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type BrowserSessionSecret = UserSecret<BrowserSessionSecretKind>;

impl actix_web::FromRequest for BrowserSessionSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.cookie(SESSION_COOKIE) else {
			return Box::pin(async { Err(AppErrorKind::NotLoggedIn.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<Db>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
		})
	}
}

// Here the "consume self when the secret is used" pattern is broken
// as the use-case for this implementation in [handle_magic_link](crate::handle_magic_link::magic_link)
// requires that the structs lives after the transformation to cookie,
// to be made into a proxy code secret, if that's the case.
impl Into<Cookie<'_>> for &BrowserSessionSecret {
	fn into(self) -> Cookie<'static> {
		// TODO: Unset the cookie on error
		Cookie::new(
			SESSION_COOKIE,
			self.code().to_str_that_i_wont_print().to_owned(),
		)
	}
}

impl BrowserSessionSecret {
	pub fn unset_cookie() -> Cookie<'static> {
		let mut cookie: Cookie<'_> = Cookie::new(SESSION_COOKIE, "");
		cookie.make_removal();
		cookie
	}
}
