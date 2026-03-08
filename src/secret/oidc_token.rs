use axum::RequestPartsExt;
use axum::extract::FromRequestParts;
use axum_extra::extract::TypedHeader;
use headers::Authorization;
use headers::authorization::Bearer;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::AuthError;

use super::browser_session::BrowserSessionSecretKind;
use super::primitive::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata, SecretType};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct OIDCTokenSecretKind;

impl UserSecretKind for OIDCTokenSecretKind {
	const PREFIX: SecretType = SecretType::OIDCToken;
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration(config: &LiveConfig) -> chrono::Duration {
		config.session_duration
	}
}

pub type OIDCTokenSecret = UserSecret<OIDCTokenSecretKind>;

impl FromRequestParts<crate::AppState> for OIDCTokenSecret {
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

		Self::try_from_string(token.token().to_string(), &state.db).await
	}
}
