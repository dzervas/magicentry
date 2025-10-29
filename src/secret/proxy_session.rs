use anyhow::Context as _;
use axum::extract::OptionalFromRequestParts;
use axum::http::request::Parts;
use axum::RequestPartsExt;
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError, ProxyError};
use crate::{AppState, OriginalUri, PROXY_SESSION_COOKIE};

use super::browser_session::BrowserSessionSecretKind;
use super::primitive::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata, SecretType};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySessionSecretKind;

impl UserSecretKind for ProxySessionSecretKind {
	const PREFIX: SecretType = SecretType::ProxySession;
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type ProxySessionSecret = UserSecret<ProxySessionSecretKind>;

// TODO: Error handling
impl OptionalFromRequestParts<AppState> for ProxySessionSecret {
	type Rejection = AppError;

	async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
		let Ok(OriginalUri(origin_url)) = parts.extract::<OriginalUri>().await else {
			// return Err(AuthError::MissingLoginLinkCode.into());
			return Ok(None);
		};

		let Ok(jar) = parts.extract::<CookieJar>().await;
		let Some(code) = jar.get(PROXY_SESSION_COOKIE) else {
			return Err(AuthError::NotLoggedIn.into());
		};


		let secret = Self::try_from_string(code.value().to_string(), &state.db).await
			.context("Failed to create proxy code secret from string")?;
		let Ok(config) = parts.extract::<LiveConfig>().await;
		let service = config.services
				.from_auth_url_origin(&origin_url.origin())
				.ok_or_else(|| AppError::Proxy(ProxyError::operation("Origin not found in service configuration")))?;

		if !service.is_user_allowed(secret.user()) {
			tracing::warn!("User {} tried to access {} with a proxy code", secret.user().email, service.name);
			return Err(AuthError::Unauthorized.into());
		}

		Ok(Some(secret))
	}
}

impl From<&ProxySessionSecret> for Cookie<'_> {
	fn from(val: &ProxySessionSecret) -> Cookie<'static> {
		Cookie::build((
			PROXY_SESSION_COOKIE,
			val.code().to_str_that_i_wont_print(),
		))
		.http_only(true)
		.path("/")
		.build()
	}
}
