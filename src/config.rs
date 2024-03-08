use serde::{Deserialize, Serialize};
use sqlx::{query, Error, SqlitePool};

use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfigFile {
	pub users: Vec<User>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigKV {
	pub key: String,
	pub value: Option<String>,
}

impl ConfigKV {
	pub async fn get(db: &SqlitePool, name: &str) -> Option<String> {
		let record = query!("SELECT * FROM config WHERE key = ?", name)
			.fetch_one(db)
			.await;

		if let Ok(record) = record {
			record.value.clone()
		} else {
			None
		}
	}

	pub async fn set(db: &SqlitePool, name: &str, new_value: &str) -> Result<(), Error> {
		query!(
				"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
				name,
				new_value,
				new_value
			)
			.execute(db)
			.await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::*;

	// #[actix_web::test]
	// async fn test_config_file() {
	// 	let toml_str = r#"
	// 		[users]
	// 		"valid@example.com" = ["realm1", "realm2"]
	// 		"#;
	// }

	#[actix_web::test]
	async fn test_config_kv() {
		let db = &db_connect().await;

		// Test set method
		ConfigKV::set(&db, "test_key", "test_value").await.unwrap();
		let value = ConfigKV::get(&db, "test_key").await.unwrap();
		assert_eq!(value, "test_value");

		ConfigKV::set(&db, "test_key", "new_value").await.unwrap();
		let value = ConfigKV::get(&db, "test_key").await.unwrap();
		assert_eq!(value, "new_value");

		// Test get method with non-existent key
		let value = ConfigKV::get(&db, "non_existent").await;
		assert!(value.is_none());
	}
}
