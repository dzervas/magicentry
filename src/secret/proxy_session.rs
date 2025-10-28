use anyhow::Context as _;
use axum::RequestPartsExt;
use actix_web::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError, DatabaseError, ProxyError};
use crate::{PROXY_ORIGIN_HEADER, PROXY_SESSION_COOKIE};

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

impl actix_web::FromRequest for ProxySessionSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(origin_header) = req.headers().get(PROXY_ORIGIN_HEADER).cloned() else {
			tracing::warn!("Got a proxy session request with no origin");
			return Box::pin(async { Err(AuthError::MissingOriginHeader.into()) });
		};
		let Some(code) = req.cookie(PROXY_SESSION_COOKIE) else {
			return Box::pin(async { Err(AuthError::NotLoggedIn.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(DatabaseError::InstanceError.into()) });
		};
		let Some(config) = req.app_data::<LiveConfig>().cloned() else {
			eprintln!("No config");
			tracing::error!("Unable to get config from request - this should not happen");
			return Box::pin(async { Err(AppError::Config("Unable to get config")) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			let origin_url = url::Url::parse(origin_header.to_str()
				.context("Failed to convert origin header to string")?)
				.context("Failed to parse origin header as URL")?;
			let secret = Self::try_from_string(code, db.get_ref()).await
				.context("Failed to create proxy session secret from string")?;
			let service = config.services
					.from_auth_url_origin(&origin_url.origin())
					.ok_or_else(|| crate::error::AppError::Proxy(ProxyError::operation("Origin not found in service configuration")))?;

			if !service.is_user_allowed(secret.user()) {
				tracing::warn!("User {} tried to access {} with a proxy session", secret.user().email, service.name);
				return Err(AuthError::Unauthorized.into());
			}

			Ok(secret)
		})
	}
}


impl From<&ProxySessionSecret> for Cookie<'_> {
	fn from(val: &ProxySessionSecret) -> Cookie<'static> {
		Cookie::build(
			PROXY_SESSION_COOKIE,
			val.code().to_str_that_i_wont_print(),
		)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish()
	}
}

// TODO: Error handling
impl axum::extract::OptionalFromRequestParts<crate::AppState> for ProxySessionSecret {
	type Rejection = crate::error::AppError;

	async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &crate::AppState) -> Result<Option<Self>, Self::Rejection> {
		let Ok(crate::OriginalUri(origin_url)) = parts.extract::<crate::OriginalUri>().await else {
			// return Err(AuthError::MissingLoginLinkCode.into());
			return Ok(None);
		};

		let Ok(jar) = parts.extract::<axum_extra::extract::CookieJar>().await;
		let Some(code) = jar.get(PROXY_SESSION_COOKIE) else {
			return Err(AuthError::NotLoggedIn.into());
		};


		let secret = Self::try_from_string(code.value().to_string(), &state.db).await
			.context("Failed to create proxy code secret from string")?;
		let service = state.config.services
				.from_auth_url_origin(&origin_url.origin())
				.ok_or_else(|| crate::error::AppError::Proxy(ProxyError::operation("Origin not found in service configuration")))?;

		if !service.is_user_allowed(secret.user()) {
			tracing::warn!("User {} tried to access {} with a proxy code", secret.user().email, service.name);
			return Err(AuthError::Unauthorized.into());
		}

		Ok(Some(secret))
	}
}

impl From<&ProxySessionSecret> for axum_extra::extract::cookie::Cookie<'_> {
	fn from(val: &ProxySessionSecret) -> axum_extra::extract::cookie::Cookie<'static> {
		axum_extra::extract::cookie::Cookie::build((
			PROXY_SESSION_COOKIE,
			val.code().to_str_that_i_wont_print(),
		))
		.http_only(true)
		.path("/")
		.build()
	}
}
