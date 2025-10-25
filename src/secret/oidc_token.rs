use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AuthError, DatabaseError};

use super::browser_session::BrowserSessionSecretKind;
use super::primitive::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata, SecretType};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct OIDCTokenSecretKind;

impl UserSecretKind for OIDCTokenSecretKind {
	const PREFIX: SecretType = SecretType::OIDCToken;
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type OIDCTokenSecret = UserSecret<OIDCTokenSecretKind>;

impl actix_web::FromRequest for OIDCTokenSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(auth_header) = req.headers().get("Authorization") else {
			return Box::pin(async { Err(AuthError::MissingAuthorizationHeader.into()) });
		};

		let Ok(auth_header_str) = auth_header.to_str() else {
			return Box::pin(async { Err(AuthError::InvalidAuthorizationHeader.into()) });
		};

		let auth_header_parts = auth_header_str.split_whitespace().collect::<Vec<&str>>();

		if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
			return Box::pin(async { Err(AuthError::InvalidAuthorizationHeader.into()) });
		}

		let Some(code) = auth_header_parts.get(1) else {
			return Box::pin(async { Err(AuthError::InvalidAuthorizationHeader.into()) });
		};

		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(DatabaseError::InstanceError.into()) });
		};

		let code = (*code).to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
				.map_err(Into::into)
		})
	}
}
