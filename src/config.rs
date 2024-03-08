use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::{query, Error, SqlitePool};

use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfigFile {
	pub users: Vec<User>,
}

impl From<ConfigFileRaw> for ConfigFile {
	fn from(raw: ConfigFileRaw) -> Self {
		let users = raw
			.users
			.into_iter()
			.map(|(email, realms)| User { email, realms })
			.collect();

		ConfigFile { users }
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFileRaw {
	pub users: HashMap<String, Vec<String>>,
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
