use serde::{Deserialize, Serialize};

use crate::CONFIG;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
	pub username: Option<String>,
	pub realms: Vec<String>,
	pub email: String,
	pub name: Option<String>,
}

impl User {
	pub fn from_config(email: &str) -> Option<User> {
		CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == email { Some(u.clone()) } else { None })
	}
}

impl PartialEq<String> for User {
	fn eq(&self, other: &String) -> bool {
		self.email == *other
	}
}

#[cfg(test)]
mod tests {
	#[allow(unused_imports)]
	use super::*;
	use crate::utils::tests::*;

	#[actix_web::test]
	async fn test_user() {
		let user = get_valid_user();

		assert!(user == user.email);
	}
}
