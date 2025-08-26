use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::{CONFIG, PROXY_ORIGIN_HEADER, PROXY_SESSION_COOKIE};

use super::browser_session::BrowserSessionSecretKind;
use super::primitive::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxySessionSecretKind;

impl UserSecretKind for ProxySessionSecretKind {
	const PREFIX: &'static str = "proxy_session";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxySessionSecret = UserSecret<ProxySessionSecretKind>;

impl actix_web::FromRequest for ProxySessionSecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(origin_header) = req.headers().get(PROXY_ORIGIN_HEADER).cloned() else {
			log::warn!("Got a proxy session request with no origin");
			return Box::pin(async { Err(AppErrorKind::MissingOriginHeader.into()) });
		};
		let Some(code) = req.cookie(PROXY_SESSION_COOKIE) else {
			return Box::pin(async { Err(AppErrorKind::NotLoggedIn.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			let origin_url = url::Url::parse(origin_header.to_str()?)?;
			let config = CONFIG.read().await;
			let service = config.services.from_auth_url_origin(&origin_url.origin()).ok_or(AppErrorKind::InvalidOriginHeader)?;
			let secret = Self::try_from_string(code, db.get_ref()).await?;

			if !service.is_user_allowed(secret.user()) {
				log::warn!("User {} tried to access {} with a proxy session", secret.user().email, service.name);
				return Err(AppErrorKind::Unauthorized.into());
			}

			Ok(secret)
		})
	}
}
