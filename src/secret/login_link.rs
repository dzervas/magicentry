use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;
use super::proxy_code::ProxyCodeSecret;
use super::{BrowserSessionSecret, EmptyMetadata, MetadataKind, SecretType};

use crate::error::{AuthError, DatabaseError, ProxyError, OidcError};
use crate::{CONFIG, PROXY_QUERY_CODE};

// This should have been an enum, but bincode (used by reindeer db) doesn't support it
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginLinkRedirect {
	pub rd: Option<url::Url>,
	#[serde(with = "crate::oidc::authorize_request::as_string", default)]
	pub oidc: Option<crate::oidc::AuthorizeRequest>,
	#[serde(with = "crate::saml::authn_request::as_string", default)]
	pub saml: Option<crate::saml::AuthnRequest>,
}

impl LoginLinkRedirect {
	pub async fn into_redirect_url(&self, browser_session_opt: Option<BrowserSessionSecret>, db: &crate::Database) -> anyhow::Result<String> {
		let mut url = self.validate_internal().await?;

		if self.rd.is_some() {
			// Redirect the user to the proxy but with an additional query secret (proxy_code)
			// so that we can identify them and hand them a proper partial session token.
			// The partial session token does not have access to the whole session
			// but only to the application that is being redirected to.
			//
			// Note that the proxy code will get forwarded to us from the proxy under a
			// different domain, so we can't just use a normal session cookie.

			let browser_session = browser_session_opt.ok_or(AuthError::NotLoggedIn)?;
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
			Err(AuthError::NoLoginLinkRedirect.into())
		}
	}

	pub async fn into_opt(self) -> Option<Self> {
		if self.validate_internal().await.is_ok() {
			Some(self)
		} else {
			None
		}
	}

	async fn validate_internal(&self) -> anyhow::Result<url::Url> {
		if u8::from(self.rd.is_some()) + u8::from(self.oidc.is_some()) + u8::from(self.saml.is_some()) > 1 {
			return Err(AuthError::MultipleLoginLinkRedirectDefinitions.into())
		}

		let config = CONFIG.read().await;

		if let Some(url) = &self.rd {
			config.services
				.from_auth_url_origin(&url.origin())
				.ok_or(ProxyError::InvalidReturnDestinationUrl)?;
			Ok(url.clone())
		} else if let Some(oidc) = &self.oidc {
			let url = url::Url::parse(&oidc.redirect_uri).map_err(|_| OidcError::InvalidRedirectUrl)?;
			config.services
				.from_oidc_redirect_url(&url)
				.ok_or(OidcError::InvalidRedirectUrl)?;
			Ok(url)
		} else if let Some(saml) = &self.saml {
			let url = url::Url::parse(&saml.acs_url).map_err(|_| ProxyError::InvalidSAMLRedirectUrl)?;
			config.services
				.from_saml_redirect_url(&url)
				.ok_or(ProxyError::InvalidSAMLRedirectUrl)?;
			Ok(url)
		} else {
			drop(config);
			Err(AuthError::NoLoginLinkRedirect.into())
		}
	}
}

impl MetadataKind for LoginLinkRedirect {
	async fn validate(&self, _: &crate::Database) -> anyhow::Result<()> {
		self.validate_internal().await?;
		Ok(())
	}
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginLinkSecretKind;

impl UserSecretKind for LoginLinkSecretKind {
	const PREFIX: SecretType = SecretType::LoginLink;
	type Metadata = Option<LoginLinkRedirect>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.link_duration }
}

pub type LoginLinkSecret = EphemeralUserSecret<LoginLinkSecretKind, BrowserSessionSecretKind>;

impl LoginLinkSecret {
	#[must_use]
	pub fn get_login_url(&self) -> String {
		format!("/login/{}", self.code().to_str_that_i_wont_print())
	}
}

impl actix_web::FromRequest for LoginLinkSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let code = if let Some(code) = req.match_info().get("magic") {
			code.to_string()
		} else {
			return Box::pin(async { Err(AuthError::MissingLoginLinkCode.into()) });
		};

		let db = if let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>() {
			db.clone()
		} else {
			return Box::pin(async { Err(DatabaseError::InstanceError.into()) });
		};

		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
				.map_err(Into::into)
		})
	}
}
