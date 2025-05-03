use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_secret::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::secret::UserSecretKind;
use super::ChildSecretMetadata;

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, url::Url>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;

impl actix_web::FromRequest for ProxyCodeSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let code = if let Some(code) = req.match_info().get("rd") {
			code.to_string()
		} else {
			return Box::pin(async { Err(AppErrorKind::MissingLoginLinkCode.into()) });
		};

		let db = req.app_data::<actix_web::web::Data<Db>>().cloned().unwrap();

		Box::pin(async move {
			Self::try_from_string(db.get_ref(), code).await
		})
	}
}
