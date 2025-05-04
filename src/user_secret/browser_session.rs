use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::SESSION_COOKIE;

use super::secret::{UserSecret, UserSecretKind};
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
		let session = if let Some(session) = req.app_data::<actix_session::Session>() {
			session
		} else {
			return Box::pin(async { Err(AppErrorKind::NotLoggedIn.into()) });
		};
		let code = if let Some(Ok(browser_session_secret)) = session.remove_as::<String>(SESSION_COOKIE) {
			browser_session_secret
		} else {
			return Box::pin(async { Err(AppErrorKind::NotLoggedIn.into()) });
		};
		let db = if let Some(db) = req.app_data::<actix_web::web::Data<Db>>() {
			db.clone()
		} else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		Box::pin(async move {
			Self::try_from_string(db.get_ref(), code).await
		})
	}
}
