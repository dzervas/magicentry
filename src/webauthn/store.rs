use reindeer::Entity;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

use crate::user::User;

#[derive(Entity, Debug, Clone, Serialize, Deserialize)]
#[entity(name = "passkey", version = 1)]
pub struct PasskeyStore {
	pub id: u32,
	#[serde(with = "crate::user::as_string")]
	pub user: User,
	#[serde(with = "as_string")]
	pub passkey: Passkey,
}

pub mod as_string {
	use super::*;

	pub fn serialize<S: serde::Serializer>(
		passkey: &Passkey,
		serializer: S,
	) -> Result<S::Ok, S::Error> {
		use serde::ser::Error;
		let json = serde_json::to_string(passkey).map_err(Error::custom)?;
		serializer.serialize_str(&json)
	}

	pub fn deserialize<'de, D: serde::Deserializer<'de>>(
		deserializer: D,
	) -> Result<Passkey, D::Error> {
		use serde::de::Error;
		let json = String::deserialize(deserializer)?;
		serde_json::from_str(&json).map_err(Error::custom)
	}
}
