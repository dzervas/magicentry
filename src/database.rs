use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool, sqlite::SqliteConnectOptions};
use std::str::FromStr;

use crate::{error::AppError, user::User};
use anyhow::Context as _;

/// `SQLite` database connection pool
pub type Database = SqlitePool;

/// Initialize the database connection and run migrations
pub async fn init_database(database_url: &str) -> Result<Database, AppError> {
	let options = SqliteConnectOptions::from_str(database_url)
		.with_context(|| format!("Failed to parse database URL: {database_url}"))?
		.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
		.shared_cache(true)
		.create_if_missing(true);

	let pool = SqlitePool::connect_with(options)
		.await
		.with_context(|| format!("Failed to connect to database: {database_url}"))?;

	// Run migrations
	sqlx::migrate!("./migrations")
		.run(&pool)
		.await
		.context("Failed to run database migrations")?;

	Ok(pool)
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
	pub async fn save(&mut self, db: &Database) -> Result<(), AppError> {
		let result = sqlx::query!(
			"INSERT INTO passkeys (user_data, passkey_data) VALUES (?, ?)",
			self.user_data,
			self.passkey_data,
		)
		.execute(db)
		.await
		.context("Failed to execute database query")?;

		self.id = Some(result.last_insert_rowid());
		Ok(())
	}

	/// Get all passkeys for a user
	pub async fn get_by_user(user: &User, db: &Database) -> Result<Vec<Self>, AppError> {
		let user_str = serde_json::to_string(user).with_context(|| {
			format!(
				"Failed to serialize user data for passkey lookup: {}",
				user.email
			)
		})?;

		let rows = sqlx::query_as!(
			Self,
			"SELECT id, user_data, passkey_data, created_at FROM passkeys WHERE user_data = ?",
			user_str
		)
		.fetch_all(db)
		.await
		.context("Failed to fetch passkeys from database")?;

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
	pub async fn save(&self, db: &Database) -> Result<(), AppError> {
		sqlx::query!(
			"INSERT INTO config_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP",
			self.key,
			self.value,
			self.value,
		)
		.execute(db)
		.await
		.context("Failed to execute database query")?;

		Ok(())
	}

	/// Get a config value by key
	pub async fn get(key: &str, db: &Database) -> Result<Option<String>, AppError> {
		let row = sqlx::query!("SELECT value FROM config_kv WHERE key = ?", key)
			.fetch_optional(db)
			.await
			.with_context(|| format!("Failed to fetch config value for key: {key}"))?;

		Ok(row.map(|r| r.value))
	}

	/// Remove a config KV pair by key
	pub async fn remove(key: &str, db: &Database) -> Result<(), AppError> {
		sqlx::query!("DELETE FROM config_kv WHERE key = ?", key)
			.execute(db)
			.await
			.context("Failed to execute database query")?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	async fn setup_test_db() -> Result<Database, AppError> {
		// Use in-memory database for tests
		init_database("sqlite::memory:").await
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
		assert!(
			ConfigKVRow::get("jwt_keypair", &db)
				.await
				.unwrap()
				.is_none()
		);
	}
}
