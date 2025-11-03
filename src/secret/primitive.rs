use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError};
use crate::database::Database;
use crate::user::User;

use super::{ChildSecretMetadata, SecretString, SecretType};
use super::metadata::MetadataKind;

/// This trait describes any kind of user secret.
/// You can think of it as a "token" but I didn't use that term to avoid
/// confusion with all the other types of tokens.
pub trait UserSecretKind: PartialEq + Send + Sync {
	const PREFIX: SecretType;
	type Metadata: MetadataKind;

	async fn duration(config: &LiveConfig) -> chrono::Duration;
}

#[derive(PartialEq, Serialize, Deserialize)]
pub(super) struct InternalUserSecret<K: UserSecretKind> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	code: SecretString,
	/// The user it authenticates
	// #[serde(with = "crate::user::as_string")]
	user: User,
	/// The time the token expires at
	expires_at: NaiveDateTime,
	created_at: NaiveDateTime,
	/// Metadata related to the secret - could be anything to nothing
	metadata: K::Metadata,
}

impl<K: UserSecretKind> InternalUserSecret<K> {
	/// Save the secret to the database
	async fn save(&self, db: &Database) -> anyhow::Result<()> {
		let user = serde_json::to_string(&self.user)?;
		let metadata = serde_json::to_string(&self.metadata)?;

		sqlx::query!(
			"INSERT INTO user_secrets (code, user, metadata, expires_at) VALUES (?, ?, ?, ?)",
			self.code,
			user,
			metadata,
			self.expires_at,
		)
			.execute(db)
		.await?;

		Ok(())
	}

	/// Get a secret from the database by code
	async fn get(code: &SecretString, db: &Database) -> anyhow::Result<Option<Self>> {
		let row = sqlx::query!(
			r#"SELECT code, user, expires_at, created_at, metadata FROM user_secrets WHERE code = ? AND expires_at > datetime('now')"#,
			code
		)
			.fetch_optional(db)
		.await?;

		let Some(row) = row else {
			return Ok(None);
		};

		// Since the metadata column in the DB is nullable, we need to handle it
		let metadata = serde_json::from_str(&row.metadata.unwrap_or_else(|| "null".to_string()))?;

		let obj = Self {
			code: row.code.try_into()?,
			user: serde_json::from_str(&row.user)?,
			expires_at: row.expires_at,
			created_at: row.created_at.unwrap_or_default(),
			metadata,
		};

		if obj.code.get_type() != &K::PREFIX {
			return Ok(None);
		}

		Ok(Some(obj))
	}

	/// Check if a user secret exists
	pub async fn exists(code: &SecretString, db: &Database) -> anyhow::Result<bool> {
		let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM user_secrets WHERE code = ?", code)
			.fetch_one(db)
		.await?;

		Ok(count > 0)
	}

	/// Remove a user secret by ID
	pub async fn remove(code: &SecretString, db: &Database) -> anyhow::Result<()> {
		sqlx::query!("DELETE FROM user_secrets WHERE code = ?", code)
			.execute(db)
		.await?;

		Ok(())
	}
}

#[derive(Serialize, Deserialize)]
pub struct UserSecret<K: UserSecretKind>(InternalUserSecret<K>);

/// Basic user secret operations
impl<K: UserSecretKind> UserSecret<K> {
	/// Create a new user secret that is bound to a user and has some metadata
	pub async fn new(user: User, metadata: K::Metadata, config: &LiveConfig, db: &Database) -> Result<Self, AppError> {
		metadata.validate(db).await?;

		let expires_at = chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(K::duration(config).await)
			.unwrap_or_else(|| panic!("Couldn't generate expiry for {:?}", K::PREFIX));

		let internal_secret = InternalUserSecret {
			code: SecretString::new(&K::PREFIX),
			user,
			expires_at,
			created_at: Utc::now().naive_utc(),
			metadata,
		};

		internal_secret.save(db).await?;

		Ok(Self(internal_secret))
	}

	/// Validate that the secret exists in the db and is not expired
	/// It also validates the metadata, if any such logic is implemented in them
	///
	/// Any failure will remove the secret from the db and return an error
	/// This is useful for cleaning up expired secrets
	pub async fn validate(&self, db: &Database) -> Result<(), AppError> {
		let prefix = K::PREFIX.as_short_str();
		if !self.0.code.to_str_that_i_wont_print().starts_with(&format!("me_{prefix}_")) {
			return Err(AppError::Auth(AuthError::InvalidSecretType));
		}

		if self.0.expires_at <= Utc::now().naive_utc() {
			InternalUserSecret::<K>::remove(&self.0.code, db).await?;
			return Err(AppError::Auth(AuthError::ExpiredSecret));
		}

		if !InternalUserSecret::<K>::exists(&self.0.code, db).await? {
			return Err(AppError::Auth(AuthError::InvalidSecret));
		}

		if self.0.metadata.validate(db).await.is_err() {
			InternalUserSecret::<K>::remove(&self.0.code, db).await?;
			return Err(AppError::Auth(AuthError::InvalidSecretMetadata));
		}

		Ok(())
	}

	/// Just delete the secret from the db
	pub async fn delete(self, db: &Database) -> Result<(), AppError> {
		InternalUserSecret::<K>::remove(&self.0.code, db).await?;
		Ok(())
	}

	/// Parse and validate a secret from a string - most probably from user controlled data
	pub async fn try_from_string(code: String, db: &Database) -> Result<Self, AppError> {
		let internal_secret = InternalUserSecret::get(&code.try_into()?, db).await?.ok_or(AuthError::InvalidSecret)?;
		let user_secret = Self(internal_secret);
		user_secret.validate(db).await?;
		Ok(user_secret)
	}

	pub const fn code(&self) -> &SecretString { &self.0.code }
	pub const fn user(&self) -> &User { &self.0.user }
	pub const fn expires_at(&self) -> NaiveDateTime { self.0.expires_at }
	pub const fn metadata(&self) -> &K::Metadata { &self.0.metadata }
	pub fn take_metadata(self) -> K::Metadata { self.0.metadata }
}

/// Operations for user secrets that are bound to a parent secret
///
/// For example a [`ProxySessionSecret`](super::proxy_session::ProxySessionSecret) is bound to a [`BrowserSessionSecret`](super::browser_session::BrowserSessionSecret)
/// since we only want the proxy session to be able to access its application data
///
/// As soon as the parent secret is deleted (or expired) the child secret will be invalidated
/// and eventually deleted as well during metadata validation
impl<P, K, M> UserSecret<K> where
P : UserSecretKind,
M : MetadataKind,
K : UserSecretKind<Metadata=ChildSecretMetadata<P, M>>,
{
	pub async fn new_child(parent: UserSecret<P>, metadata: M, config: &LiveConfig, db: &Database) -> Result<Self, AppError> {
		Self::new(parent.user().clone(), ChildSecretMetadata::new(parent, metadata), config, db).await
	}

	pub const fn child_metadata<'a>(&'a self) -> &'a M where P: 'a { self.0.metadata.metadata() }
}

// TODO: Create a blanket implementation of FromRequest for UserSecret instances that implement a FromRequestAsync trait so that the async-related boilerplate can go away

#[cfg(test)]
mod tests {
	use crate::{database::init_database, secret::LoginLinkSecret};

	use super::*;

	async fn setup_test_db() -> Result<Database, AppError> {
		// Use in-memory database for tests
		init_database("sqlite::memory:").await
	}

	async fn db_fetch(code: SecretString, db: &Database) -> i64 {
		sqlx::query_scalar("SELECT COUNT(*) FROM user_secrets WHERE code = ?")
			.bind(code)
			.fetch_one(db)
			.await
			.unwrap()
	}

	#[tokio::test]
	async fn test_user_secret_crud() {
		let config = crate::CONFIG.read().await.clone().into();
		let db = setup_test_db().await.unwrap();
		let user = crate::user::User {
			email: "hello@world.com".to_string(),
			username: "helloworld".to_string(),
			name: "Hello World".to_string(),
			realms: vec!["test".to_string()],
		};

		let login_link = LoginLinkSecret::new(user.clone(), None, &config, &db).await.unwrap();
		let login_link_code = login_link
			.get_login_url()
			.split('/')
			.next_back()
			.unwrap()
			.to_string();

		// Test get
		let retrieved = LoginLinkSecret::try_from_string(login_link_code, &db).await.unwrap();
		let retrieved_code = retrieved.code().clone();
		assert_eq!(retrieved.user(), &user);

		let db_fetched = db_fetch(retrieved.code().clone(), &db).await;
		assert_eq!(db_fetched, 1);

		let session = retrieved.exchange(&config, &db).await.unwrap();
		let session_code = session.code().clone();
		let db_fetched = db_fetch(session.code().clone(), &db).await;
		assert_eq!(db_fetched, 1);
		let db_fetched = db_fetch(retrieved_code.clone(), &db).await;
		assert_eq!(db_fetched, 0);

		session.delete(&db).await.unwrap();
		let db_fetched = db_fetch(session_code.clone(), &db).await;
		assert_eq!(db_fetched, 0);
	}
}
