use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};

use super::browser_session::BrowserSessionSecretKind;
use super::primitive::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct OIDCTokenSecretKind;

impl UserSecretKind for OIDCTokenSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type OIDCTokenSecret = UserSecret<OIDCTokenSecretKind>;

impl actix_web::FromRequest for OIDCTokenSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(auth_header) = req.headers().get("Authorization") else {
			return Box::pin(async { Err(AppErrorKind::MissingAuthorizationHeader.into()) });
		};

		let Ok(auth_header_str) = auth_header.to_str() else {
			return Box::pin(async { Err(AppErrorKind::InvalidAuthorizationHeader.into()) });
		};

		let auth_header_parts = auth_header_str.split_whitespace().collect::<Vec<&str>>();

		if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
			return Box::pin(async { Err(AppErrorKind::InvalidAuthorizationHeader.into()) });
		}

		let Some(code) = auth_header_parts.get(1) else {
			return Box::pin(async { Err(AppErrorKind::InvalidAuthorizationHeader.into()) });
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
