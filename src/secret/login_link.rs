use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;
use super::proxy_code::ProxyCodeSecret;
use super::{BrowserSessionSecret, EmptyMetadata, MetadataKind};

use crate::error::{AppErrorKind, Result};
use crate::{CONFIG, PROXY_QUERY_CODE};

// This should have been an enum, but bincode (used by reindeer db) doesn't support it
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoginLinkRedirect {
	pub rd: Option<url::Url>,
	#[serde(with = "crate::oidc::authorize_request::as_string", default)]
	pub oidc: Option<crate::oidc::AuthorizeRequest>,
	#[serde(with = "crate::saml::authn_request::as_string", default)]
	pub saml: Option<crate::saml::AuthnRequest>,
}

impl LoginLinkRedirect {
	pub async fn into_redirect_url(&self, browser_session_opt: Option<BrowserSessionSecret>, db: &crate::Database) -> Result<String> {
		let mut url = self.validate_internal().await?;

		if self.rd.is_some() {
			// Redirect the user to the proxy but with an additional query secret (proxy_code)
			// so that we can identify them and hand them a proper partial session token.
			// The partial session token does not have access to the whole session
			// but only to the application that is being redirected to.
			//
			// Note that the proxy code will get forwarded to us from the proxy under a
			// different domain, so we can't just use a normal session cookie.

			let browser_session = browser_session_opt.ok_or(AppErrorKind::NotLoggedIn)?;
			let proxy_code = ProxyCodeSecret::new_child(browser_session, EmptyMetadata(), db).await?;
			url
				.query_pairs_mut()
				.append_pair(PROXY_QUERY_CODE, &proxy_code.code().to_str_that_i_wont_print());
			Ok(url.to_string())
		} else if let Some(oidc) = &self.oidc {
			Ok(format!("/oidc/authorize?{}", serde_qs::to_string(oidc)?))
		} else if let Some(saml) = &self.saml {
			Ok(format!("/saml/sso?{}", serde_qs::to_string(saml)?))
		} else {
			Err(AppErrorKind::NoLoginLinkRedirect.into())
		}
	}

	pub async fn into_opt(self) -> Option<Self> {
		if self.validate_internal().await.is_ok() {
			Some(self)
		} else {
			None
		}
	}

	async fn validate_internal(&self) -> Result<url::Url> {
		let config = CONFIG.read().await;

		if self.rd.is_some() as u8 + self.oidc.is_some() as u8 + self.saml.is_some() as u8 > 1 {
			return Err(AppErrorKind::MultipleLoginLinkRedirectDefinitions.into())
		}

		if let Some(url) = &self.rd {
			config.services
				.from_auth_url_origin(&url.origin())
				.ok_or(AppErrorKind::InvalidReturnDestinationUrl)?;
			Ok(url.clone())
		} else if let Some(oidc) = &self.oidc {
			let url = url::Url::parse(&oidc.redirect_uri).map_err(|_| AppErrorKind::InvalidOIDCRedirectUrl)?;
			config.services
				.from_oidc_redirect_url(&url)
				.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
			Ok(url)
		} else if let Some(saml) = &self.saml {
			let url = url::Url::parse(&saml.acs_url).map_err(|_| AppErrorKind::InvalidSAMLRedirectUrl)?;
			config.services
				.from_saml_redirect_url(&url)
				.ok_or(AppErrorKind::InvalidSAMLRedirectUrl)?;
			Ok(url)
		} else {
			Err(AppErrorKind::NoLoginLinkRedirect.into())
		}
	}
}

impl MetadataKind for LoginLinkRedirect {
	async fn validate(&self, _: &crate::Database) -> Result<()> {
		self.validate_internal().await?;
		Ok(())
	}
}

pub struct LoginLinkSecretKind;

impl UserSecretKind for LoginLinkSecretKind {
	const PREFIX: &'static str = "login";
	type Metadata = Option<LoginLinkRedirect>;

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

		let db = if let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>() {
			db.clone()
		} else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};

		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
		})
	}
}
