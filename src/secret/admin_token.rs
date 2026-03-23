use axum::RequestPartsExt;
use axum::extract::FromRequestParts;
use axum_extra::extract::TypedHeader;
use headers::Authorization;
use headers::authorization::Bearer;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::AuthError;
use crate::secret::MetadataKind;

use super::SecretType;
use super::primitive::{UserSecret, UserSecretKind};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminApiTokenSecretKind;

impl UserSecretKind for AdminApiTokenSecretKind {
	const PREFIX: SecretType = SecretType::OIDCToken;
	type Metadata = AdminApiTokenMetadata;

	async fn duration(config: &LiveConfig) -> chrono::Duration {
		config.session_duration
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminApiTokenMetadata {
	pub description: String,
}

impl MetadataKind for AdminApiTokenMetadata {}

pub type AdminApiTokenSecret = UserSecret<AdminApiTokenSecretKind>;

impl FromRequestParts<crate::AppState> for AdminApiTokenSecret {
	type Rejection = crate::error::AppError;

	async fn from_request_parts(
		parts: &mut axum::http::request::Parts,
		state: &crate::AppState,
	) -> Result<Self, Self::Rejection> {
		let Ok(TypedHeader(Authorization(token))) =
			parts.extract::<TypedHeader<Authorization<Bearer>>>().await
		else {
			return Err(AuthError::MissingLoginLinkCode.into());
		};
		let Ok(config) = parts.extract::<LiveConfig>().await else {
			return Err("Could not extract config".into());
		};

		Self::try_from_string(token.token().to_string(), &config, &state.db).await
	}
}
