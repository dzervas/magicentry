use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CONFIG;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
	pub username: String,
	pub realms: Vec<String>,
	pub email: String,
	pub name: String,
}

impl User {
	pub async fn from_email(email: &str) -> Option<Self> {
		CONFIG.read().await.users
			.iter()
			.find(|u| u.email == email).cloned()
	}

	#[must_use]
	pub fn has_any_realm(&self, realms: &[String]) -> bool {
		self.realms.contains(
			&"all".to_string()) ||
			self.realms.iter().any(|r| realms.contains(r))
	}

	pub fn from_config_blocking(email: &str) -> Option<Self> {
		let mut i = 0;
		let config = loop {
			if let Ok(guard) = CONFIG.try_read() {
				break guard;
			}

			std::thread::sleep(std::time::Duration::from_millis(1));

			i += 1;
			if i > 100 {
				log::warn!("Could not sync-lock the config to read the users - this is a bug");
				return None;
			}
		};

		config.users
			.iter()
			.find(|u| u.email == email).cloned()
	}
}

impl PartialEq<String> for User {
	fn eq(&self, other: &String) -> bool {
		self.email == *other
	}
}

impl PartialEq<&str> for User {
	fn eq(&self, other: &&str) -> bool {
		self.email == *other
	}
}

// XXX: Ok but what about collisions? Does it have an impact?
/// MD5 is only used to generate a UUID for this user, which is not a secret,
/// not used for authentication and not a user-provided value.
/// webauthn-rs expects a `UUIDv4` and the only hash function producing 16 bytes is MD5.
impl From<&User> for Uuid {
	fn from(val: &User) -> Self {
		let hash = md5::compute(val.email.as_bytes());
		Self::from_bytes(hash.0)
	}
}

pub mod as_string {
	use super::User;
	use serde::Deserialize as _;

	pub fn serialize<S: serde::Serializer>(user: &User, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&user.email)
	}

	pub fn deserialize<'de, D: serde::Deserializer<'de>>(
		deserializer: D,
	) -> Result<User, D::Error> {
		let email = String::deserialize(deserializer)?;
		// TODO: Do not block
		User::from_config_blocking(&email).ok_or_else(|| serde::de::Error::custom("User not found"))
	}
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use super::*;
	use crate::utils::tests::*;

	#[actix_web::test]
	async fn test_user() {
		let user = get_valid_user().await;

		assert!(user == user.email);
	}
}
