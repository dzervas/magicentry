use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::{CONFIG, PROXY_ORIGIN_HEADER, PROXY_QUERY_CODE};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::primitive::UserSecretKind;
use super::{ChildSecretMetadata, EmptyMetadata};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy_code";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;

impl actix_web::FromRequest for ProxyCodeSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(origin_header) = req.headers().get(PROXY_ORIGIN_HEADER).cloned() else {
			log::warn!("Got a proxy code request with no origin");
			return Box::pin(async { Err(AppErrorKind::MissingOriginHeader.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		Box::pin(async move {
			let origin_url = url::Url::parse(origin_header.to_str()?)?;

			let code = origin_url
				.query_pairs()
				.find(|e| e.0.to_lowercase() == PROXY_QUERY_CODE)
				.ok_or(AppErrorKind::CouldNotParseXOriginalURIHeader)?;

			let secret = Self::try_from_string(code.1.to_string(), db.get_ref()).await?;
			let service = {
				let config = CONFIG.read().await;
				config.services
					.from_auth_url_origin(&origin_url.origin())
					.ok_or(AppErrorKind::InvalidOriginHeader)?
			};

			if !service.is_user_allowed(secret.user()) {
				log::warn!("User {} tried to access {} with a proxy code", secret.user().email, service.name);
				return Err(AppErrorKind::Unauthorized.into());
			}

			Ok(secret)
		})
	}
}
