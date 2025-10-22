use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, FromRow};
use std::str::FromStr;

use crate::error::Result;
use crate::user::User;

/// `SQLite` database connection pool
pub type Database = SqlitePool;

/// Initialize the database connection and run migrations
pub async fn init_database(database_url: &str) -> Result<Database> {
	let options = SqliteConnectOptions::from_str(database_url)?
		.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
		.shared_cache(true)
		.create_if_missing(true);
	
	let pool = SqlitePool::connect_with(options).await?;
	
	// Run migrations
	sqlx::migrate!("./migrations").run(&pool).await?;
	
	Ok(pool)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
pub enum UserSecretType {
	ApiKey,
	BrowserSession,
	LoginLink,
	MagicToken,
	OIDCAuthCode,
	OIDCToken,
	ProxyCode,
	ProxySession,
	WebAuthnAuth,
	WebAuthnReg,
}

impl UserSecretType {
	#[must_use]
	pub const fn as_short_str(&self) -> &'static str {
		match self {
			Self::ApiKey => "aa",
			Self::BrowserSession => "bs",
			Self::LoginLink => "ll",
			Self::MagicToken => "mt",
			Self::OIDCAuthCode => "oa",
			Self::OIDCToken => "ot",
			Self::ProxyCode => "pc",
			Self::ProxySession => "ps",
			Self::WebAuthnAuth => "wa",
			Self::WebAuthnReg => "wr",
		}
	}
}

/// Represents a user secret stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserSecretRow {
	pub id: String,
	pub secret_type: UserSecretType,
	pub user_data: String,
	pub expires_at: NaiveDateTime,
	pub metadata: String,
	pub created_at: Option<NaiveDateTime>,
}

impl UserSecretRow {
	/// Save a user secret to the database
	pub async fn save(&self, db: &Database) -> Result<()> {
		sqlx::query!(
			"INSERT INTO user_secrets (id, secret_type, user_data, expires_at, metadata) VALUES (?, ?, ?, ?, ?)",
			self.id,
			self.secret_type,
			self.user_data,
			self.expires_at,
			self.metadata,
		)
		.execute(db)
		.await?;
		
		Ok(())
	}
	
	/// Get a user secret by ID
	pub async fn get(id: &str, db: &Database) -> Result<Option<Self>> {
		let row = sqlx::query_as!(Self,
			r#"SELECT id, secret_type AS "secret_type: UserSecretType", user_data, expires_at, metadata, created_at FROM user_secrets WHERE id = ?"#,
			id
		)
		.fetch_optional(db)
		.await?;
		
		Ok(row)
	}
	
	/// Check if a user secret exists
	pub async fn exists(id: &str, db: &Database) -> Result<bool> {
		let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM user_secrets WHERE id = ?", id)
		.fetch_one(db)
		.await?;
		
		Ok(count > 0)
	}
	
	/// Remove a user secret by ID
	pub async fn remove(id: &str, db: &Database) -> Result<()> {
		sqlx::query!("DELETE FROM user_secrets WHERE id = ?", id)
		.execute(db)
		.await?;
		
		Ok(())
	}
	
}

/// Represents a passkey stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasskeyRow {
	pub id: Option<i64>,
	pub user_data: String,
	pub passkey_data: String,
	pub created_at: Option<NaiveDateTime>,
}

impl PasskeyRow {
	/// Save a passkey to the database
	pub async fn save(&mut self, db: &Database) -> Result<()> {
		let result = sqlx::query!(
			"INSERT INTO passkeys (user_data, passkey_data) VALUES (?, ?)",
			self.user_data,
			self.passkey_data,
		)
		.execute(db)
		.await?;
		
		self.id = Some(result.last_insert_rowid());
		Ok(())
	}
	
	/// Get all passkeys for a user
	pub async fn get_by_user(user: &User, db: &Database) -> Result<Vec<Self>> {
		let user_str = serde_json::to_string(user)?;
		
		let rows = sqlx::query_as!(
			Self,
			"SELECT id, user_data, passkey_data, created_at FROM passkeys WHERE user_data = ?",
			user_str
		)
		.fetch_all(db)
		.await?;
		
		Ok(rows)
	}
}

/// Represents a config KV pair stored in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConfigKVRow {
	pub key: String,
	pub value: String,
	pub updated_at: Option<NaiveDateTime>,
}

impl ConfigKVRow {
	/// Save or update a config KV pair
	pub async fn save(&self, db: &Database) -> Result<()> {
		sqlx::query!(
			"INSERT INTO config_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP",
			self.key,
			self.value,
			self.value,
		)
		.execute(db)
		.await?;
		
		Ok(())
	}
	
	/// Get a config value by key
	pub async fn get(key: &str, db: &Database) -> Result<Option<String>> {
		let row = sqlx::query!("SELECT value FROM config_kv WHERE key = ?", key)
		.fetch_optional(db)
		.await?;
		
		Ok(row.map(|r| r.value))
	}
	
	/// Remove a config KV pair by key
	pub async fn remove(key: &str, db: &Database) -> Result<()> {
		sqlx::query!("DELETE FROM config_kv WHERE key = ?", key)
		.execute(db)
		.await?;
		
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	async fn setup_test_db() -> Result<Database> {
		// Use in-memory database for tests
		init_database("sqlite::memory:").await
	}

	#[tokio::test]
	async fn test_user_secret_crud() {
		let db = setup_test_db().await.unwrap();
		
		let secret = UserSecretRow {
			id: "test_secret_123".to_string(),
			secret_type: UserSecretType::LoginLink,
			user_data: r#"{"email":"test@example.com","username":"test","name":"Test User","realms":["test"]}"#.to_string(),
			expires_at: chrono::Utc::now().naive_utc() + chrono::Duration::hours(1),
			metadata: "{}".to_string(),
			created_at: None,
		};

		// Test save
		secret.save(&db).await.unwrap();

		// Test get
		let retrieved = UserSecretRow::get("test_secret_123", &db).await.unwrap().unwrap();
		assert_eq!(retrieved.id, secret.id);
		assert_eq!(retrieved.secret_type, secret.secret_type);
		assert_eq!(retrieved.user_data, secret.user_data);

		// Test exists
		assert!(UserSecretRow::exists("test_secret_123", &db).await.unwrap());
		assert!(!UserSecretRow::exists("nonexistent", &db).await.unwrap());

		// Test remove
		UserSecretRow::remove("test_secret_123", &db).await.unwrap();
		assert!(!UserSecretRow::exists("test_secret_123", &db).await.unwrap());
	}

	#[tokio::test]
	async fn test_config_kv_crud() {
		let db = setup_test_db().await.unwrap();
		
		let config = ConfigKVRow {
			key: "jwt_keypair".to_string(),
			value: "test_keypair_value".to_string(),
			updated_at: None,
		};

		// Test save
		config.save(&db).await.unwrap();

		// Test get
		let value = ConfigKVRow::get("jwt_keypair", &db).await.unwrap().unwrap();
		assert_eq!(value, "test_keypair_value");

		// Test update (save again with different value)
		let updated_config = ConfigKVRow {
			key: "jwt_keypair".to_string(),
			value: "updated_keypair_value".to_string(),
			updated_at: None,
		};
		updated_config.save(&db).await.unwrap();
		
		let updated_value = ConfigKVRow::get("jwt_keypair", &db).await.unwrap().unwrap();
		assert_eq!(updated_value, "updated_keypair_value");

		// Test remove
		ConfigKVRow::remove("jwt_keypair", &db).await.unwrap();
		assert!(ConfigKVRow::get("jwt_keypair", &db).await.unwrap().is_none());
	}

}
