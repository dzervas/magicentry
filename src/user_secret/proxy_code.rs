use actix_web::cookie::Cookie;
use futures::future::BoxFuture;
use reindeer::Db;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::PROXY_QUERY_CODE;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::primitive::UserSecretKind;
use super::{ChildSecretMetadata, MetadataKind};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

		// if config.force_https_redirects {
		// 	if self.url.scheme() != "https" {
		// 		self.url.set_scheme("https").map_err(|_| {
		// 			AppErrorKind::InvalidReturnDestinationUrl
		// 		})?;
		// 	}
		// }

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

impl Into<Cookie<'_>> for ProxyRedirectUrl {
	fn into(self) -> Cookie<'static> {
		Cookie::new(
			PROXY_QUERY_CODE,
			self.url.to_string(),
		)
	}
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, ProxyRedirectUrl>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;

impl ProxyCodeSecret {
	pub fn final_redirect_url(&self) -> Result<url::Url> {
		let mut redirect_url = self.child_metadata().url.clone();
		redirect_url.query_pairs_mut()
			.append_pair(PROXY_QUERY_CODE, self.code().to_str_that_i_wont_print());

		Ok(redirect_url)
	}
}

impl actix_web::FromRequest for ProxyCodeSecret {
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
