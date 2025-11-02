use anyhow::Context as _;
use axum::extract::OptionalFromRequestParts;
use axum::http::request::Parts;
use axum::RequestPartsExt;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError, ProxyError};
use crate::{AppState, OriginalUri, CONFIG, PROXY_QUERY_CODE};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::proxy_session::ProxySessionSecretKind;
use super::primitive::UserSecretKind;
use super::{ChildSecretMetadata, EmptyMetadata, SecretType};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: SecretType = SecretType::ProxyCode;
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;

// TODO: Error handling
impl OptionalFromRequestParts<AppState> for ProxyCodeSecret {
	type Rejection = AppError;

	async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
		let Ok(OriginalUri(origin_url)) = parts.extract::<OriginalUri>().await else {
			return Ok(None);
		};

		let Some(code) = origin_url
			.query_pairs()
			.find(|e| e.0.to_lowercase() == PROXY_QUERY_CODE) else {
			return Ok(None);
		};

		let secret = Self::try_from_string(code.1.to_string(), &state.db).await
			.context("Failed to create proxy code secret from string")?;
		let service = {
			let config = CONFIG.read().await;
			config.services
				.from_auth_url_origin(&origin_url.origin())
				.ok_or_else(|| AppError::Proxy(ProxyError::operation("Origin not found in service configuration")))?
		};

		if !service.is_user_allowed(secret.user()) {
			tracing::warn!("User {} tried to access {} with a proxy code", secret.user().email, service.name);
			return Err(AuthError::Unauthorized.into());
		}

		Ok(Some(secret))
	}
}
