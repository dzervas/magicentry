use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_secret::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::secret::UserSecretKind;
use super::{ChildSecretMetadata, EmptyMetadata, MetadataKind};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyRedirectUrl {
	#[serde(rename = "rd")]
	pub url: url::Url,
}

impl MetadataKind for ProxyRedirectUrl {
	async fn validate(&self, _: &Db) -> Result<()> {
		let config = crate::CONFIG.read().await;
		if !config
			.allowed_origins()
			.iter()
			.any(|origin| self.url.origin().ascii_serialization() == origin.as_str())
		{
			return Err(AppErrorKind::InvalidReturnDestinationUrl.into());
		}

		Ok(())
	}
}

impl From<url::Url> for ProxyRedirectUrl {
	fn from(url: url::Url) -> Self {
		Self{ url }
	}
}

impl Into<url::Url> for ProxyRedirectUrl {
	fn into(self) -> url::Url {
		self.url
	}
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

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
