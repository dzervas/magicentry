use reindeer::Entity;
use serde::{Deserialize, Serialize};

#[derive(Entity, Debug, Clone, Serialize, Deserialize)]
#[entity(name = "passkey", version = 1)]
pub struct PasskeyStore {
	pub id: Vec<u8>,
	pub rp_id: String,
	pub user_handle: Option<Vec<u8>>,
	pub counter: u32,
	pub user: String,
}
