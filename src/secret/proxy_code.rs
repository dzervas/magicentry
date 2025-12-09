use axum::RequestPartsExt;
use axum::extract::OptionalFromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError, ProxyError};
use crate::{AppState, CONFIG, OriginalUri, PROXY_QUERY_CODE};

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::primitive::UserSecretKind;
use super::proxy_session::ProxySessionSecretKind;
use super::{ChildSecretMetadata, EmptyMetadata, SecretType};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: SecretType = SecretType::ProxyCode;
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration(config: &LiveConfig) -> chrono::Duration {
		config.session_duration
	}
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;

// TODO: Error handling
impl OptionalFromRequestParts<AppState> for ProxyCodeSecret {
	type Rejection = AppError;

	async fn from_request_parts(
		parts: &mut Parts,
		state: &AppState,
	) -> Result<Option<Self>, Self::Rejection> {
		let Ok(OriginalUri(origin_url)) = parts.extract::<OriginalUri>().await else {
			return Ok(None);
		};

		let Some(code) = origin_url
			.query_pairs()
			.find(|e| e.0.to_lowercase() == PROXY_QUERY_CODE)
		else {
			return Ok(None);
		};

		let code_value = code.1.to_string();
		let secret = match Self::try_from_string(code_value, &state.db).await {
			Ok(secret) => secret,
			Err(AppError::Auth(
				AuthError::ExpiredSecret
				| AuthError::InvalidSecret
				| AuthError::InvalidSecretType
				| AuthError::InvalidSecretMetadata,
			)) => {
				tracing::warn!("Ignoring invalid proxy code during auth-url status check");
				return Ok(None);
			}
			Err(err) => {
				tracing::error!(error = %err, "Failed to create proxy code secret from string");
				return Err(err);
			}
		};
		let service = {
			let config = CONFIG.read().await;
			config
				.services
				.from_auth_url_origin(&origin_url.origin())
				.ok_or_else(|| {
					AppError::Proxy(ProxyError::operation(
						"Origin not found in service configuration",
					))
				})?
		};

		if !service.is_user_allowed(secret.user()) {
			tracing::warn!(
				"User {} tried to access {} with a proxy code",
				secret.user().email,
				service.name
			);
			return Err(AuthError::Unauthorized.into());
		}

		Ok(Some(secret))
	}
}
