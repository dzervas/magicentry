use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

use crate::database::{Database, PasskeyRow};
use anyhow::Result;
use crate::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyStore {
	pub id: Option<i64>,
	#[serde(with = "crate::user::as_string")]
	pub user: User,
	#[serde(with = "as_string")]
	pub passkey: Passkey,
}

impl PasskeyStore {
	/// Save the passkey to the database
	pub async fn save(&mut self, db: &Database) -> Result<()> {
		let user_str = serde_json::to_string(&self.user)?;
		let passkey_str = serde_json::to_string(&self.passkey)?;
		
		let mut row = PasskeyRow {
			id: self.id,
			user_data: user_str,
			passkey_data: passkey_str,
			created_at: None,
		};
		
		row.save(db).await?;
		self.id = row.id;
		Ok(())
	}
	
	/// Get all passkeys for a user
	pub async fn get_by_user(user: &User, db: &Database) -> Result<Vec<Self>> {
		let rows = PasskeyRow::get_by_user(user, db).await?;
		let mut passkeys = Vec::new();
		
		for row in rows {
			let user: User = serde_json::from_str(&row.user_data)?;
			let passkey: Passkey = serde_json::from_str(&row.passkey_data)?;
			
			passkeys.push(Self {
				id: row.id,
				user,
				passkey,
			});
		}
		
		Ok(passkeys)
	}
}

pub mod as_string {
	use super::Passkey;
	use serde::Deserialize;

	pub fn serialize<S: serde::Serializer>(
		passkey: &Passkey,
		serializer: S,
	) -> std::result::Result<S::Ok, S::Error> {
		use serde::ser::Error;
		let json = serde_json::to_string(passkey).map_err(S::Error::custom)?;
		serializer.serialize_str(&json)
	}

	pub fn deserialize<'de, D: serde::Deserializer<'de>>(
		deserializer: D,
	) -> std::result::Result<Passkey, D::Error> {
		use serde::de::Error;
		let json = String::deserialize(deserializer)?;
		serde_json::from_str(&json).map_err(D::Error::custom)
	}
}
