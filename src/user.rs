use actix_session::Session;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::token::SessionToken;
use crate::{CONFIG, SESSION_COOKIE};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
	pub username: Option<String>,
	pub realms: Vec<String>,
	pub email: String,
	pub name: Option<String>,
}

impl User {
	pub async fn from_session(db: &SqlitePool, session: &Session) -> Result<Option<User>> {
		if let Some(session_id) = session.get::<String>(SESSION_COOKIE).unwrap_or(None) {
			Ok(SessionToken::from_code(db, session_id.as_str()).await?.get_user())
		} else {
			session.remove(SESSION_COOKIE);
			Ok(None)
		}
	}

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
