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
	pub passkey: Passkey,
	pub counter: u32,
}
