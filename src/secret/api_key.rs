use chrono::{Duration, NaiveDateTime, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::user::User;
use crate::{CONFIG, PROXY_ORIGIN_HEADER};

use super::primitive::{InternalUserSecret, UserSecret, UserSecretKind};
use super::{MetadataKind, SecretString};
use crate::database::{Database, UserSecretRow};

/// Metadata attached to an API key, storing the service name it grants access to.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiKeyMetadata {
	pub service: String,
}

impl MetadataKind for ApiKeyMetadata {
	async fn validate(&self, _: &Database) -> Result<()> {
		let config = CONFIG.read().await;
		if config.services.get(&self.service).is_none() {
			return Err(AppErrorKind::NotFound.into());
		}
		Ok(())
	}
}

/// Secret kind used for API keys.
#[derive(PartialEq, Serialize, Deserialize)]
pub struct ApiKeySecretKind;

impl UserSecretKind for ApiKeySecretKind {
	const PREFIX: &'static str = "api";
	type Metadata = ApiKeyMetadata;

	async fn duration() -> chrono::Duration {
		CONFIG.read().await.api_key_max_expiration
	}
}

/// API key secret type.
pub type ApiKeySecret = UserSecret<ApiKeySecretKind>;

impl ApiKeySecret {
	/// Create a new API key with a custom expiration.
	pub async fn new_with_expiration(
		user: User,
		service: String,
		duration: Duration,
		db: &Database,
	) -> Result<Self> {
		let max = ApiKeySecretKind::duration().await;
		let final_duration = if max.num_seconds() == 0 || duration <= max {
			duration
		} else {
			max
		};
		let expires_at = if final_duration.num_seconds() == 0 {
			NaiveDateTime::MAX
		} else {
			Utc::now()
				.naive_utc()
				.checked_add_signed(final_duration)
				.ok_or(AppErrorKind::InvalidDuration)?
		};
		let internal = InternalUserSecret {
			code: SecretString::new(ApiKeySecretKind::PREFIX),
			user,
			expires_at,
			metadata: ApiKeyMetadata { service },
		};
		internal.save(db).await?;
		Ok(Self(internal))
	}

	/// List API keys for a user and service.
	pub async fn list(user: &User, service: &str, db: &Database) -> Result<Vec<ApiKeyInfo>> {
		let user_str = serde_json::to_string(user)?;
		let rows = sqlx::query_as::<_, UserSecretRow>(
"SELECT id, secret_type, user_data, expires_at, metadata, created_at FROM user_secrets WHERE secret_type = ? AND user_data = ?",
)
.bind(ApiKeySecretKind::PREFIX)
.bind(user_str)
.fetch_all(db)
.await?;

		let mut keys = Vec::new();
		for row in rows {
			let meta: ApiKeyMetadata = serde_json::from_str(&row.metadata)?;
			if meta.service != service {
				continue;
			}
			let display = format!("{}…", &row.id[..row.id.len().min(8)]);
			let expires_at = if row.expires_at == NaiveDateTime::MAX {
				None
			} else {
				Some(row.expires_at)
			};
			keys.push(ApiKeyInfo {
				id: row.id,
				display,
				expires_at,
			});
		}
		Ok(keys)
	}

	/// Get the associated service name.
	pub fn service(&self) -> &str {
		&self.0.metadata.service
	}
}

/// Public representation of an API key for listing purposes.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyInfo {
	pub id: String,
	pub display: String,
	pub expires_at: Option<NaiveDateTime>,
}

impl actix_web::FromRequest for ApiKeySecret {
	type Error = crate::error::Error;
	type Future = BoxFuture<'static, Result<Self>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(key_header) = req.headers().get("X-Api-Key").cloned() else {
			return Box::pin(async { Err(AppErrorKind::NotLoggedIn.into()) });
		};
		let Some(origin_header) = req.headers().get(PROXY_ORIGIN_HEADER).cloned() else {
			return Box::pin(async { Err(AppErrorKind::MissingOriginHeader.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<Database>>().cloned() else {
			return Box::pin(async { Err(AppErrorKind::DatabaseInstanceError.into()) });
		};
		Box::pin(async move {
			let key = key_header.to_str()?.to_string();
			let origin_url = url::Url::parse(origin_header.to_str()?)?;
			let config = CONFIG.read().await;
			let service = config
				.services
				.from_auth_url_origin(&origin_url.origin())
				.ok_or(AppErrorKind::InvalidOriginHeader)?;
			let secret = ApiKeySecret::try_from_string(key, db.get_ref()).await?;
			if secret.service() != service.name {
				return Err(AppErrorKind::Unauthorized.into());
			}
			if !service.is_user_allowed(secret.user()) {
				return Err(AppErrorKind::Unauthorized.into());
			}
			Ok(secret)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	#[tokio::test]
	async fn test_api_key_crud() {
		let db = db_connect().await;
		let user = get_valid_user().await;
		let key = ApiKeySecret::new_with_expiration(
			user.clone(),
			"example".to_string(),
			Duration::try_seconds(60).unwrap(),
			&db,
		)
		.await
		.unwrap();
		let id = key.code().to_str_that_i_wont_print().to_string();
		let list = ApiKeySecret::list(&user, "example", &db).await.unwrap();
		assert_eq!(list.len(), 1);
		let fetched = ApiKeySecret::try_from_string(id.clone(), &db)
			.await
			.unwrap();
		let new_key = ApiKeySecret::new_with_expiration(
			user.clone(),
			"example".to_string(),
			Duration::try_seconds(60).unwrap(),
			&db,
		)
		.await
		.unwrap();
		fetched.delete(&db).await.unwrap();
		let new_id = new_key.code().to_str_that_i_wont_print().to_string();
		let list = ApiKeySecret::list(&user, "example", &db).await.unwrap();
		assert_eq!(list.len(), 1);
		let fetched_new = ApiKeySecret::try_from_string(new_id.clone(), &db)
			.await
			.unwrap();
		fetched_new.delete(&db).await.unwrap();
		let list = ApiKeySecret::list(&user, "example", &db).await.unwrap();
		assert!(list.is_empty());
	}
}
