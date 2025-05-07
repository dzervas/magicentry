use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::PROXY_QUERY_CODE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::primitive::UserSecretKind;
use super::ChildSecretMetadata;

#[derive(PartialEq, Serialize, Deserialize)]
pub struct OIDCAuthCodeSecretKind;

impl UserSecretKind for OIDCAuthCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, AuthorizeRequest>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type OIDCAuthCodeSecret = EphemeralUserSecret<OIDCAuthCodeSecretKind, ProxySessionSecretKind>;

impl actix_web::FromRequest for OIDCAuthCodeSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.match_info().get(PROXY_QUERY_CODE) else {
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
