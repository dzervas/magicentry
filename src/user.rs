use std::result::Result as StdResult;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::SqlitePool;

use crate::model::{Token, TokenKind};
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
	pub async fn from_session(db: &SqlitePool, session: actix_session::Session) -> Result<Option<User>> {
		if let Some(session_id) = session.get::<String>(SESSION_COOKIE).unwrap_or(None) {
			User::from_session_id(db, session_id.as_str()).await
		} else {
			Ok(None)
		}
	}

	pub async fn from_session_id(db: &SqlitePool, session_id: &str) -> Result<Option<User>> {
		let session = Token::from_code(db, session_id, TokenKind::Session).await;
		if let Ok(session) = session {
			let user = session.get_user();
			if user.is_none() {
				session.delete(&db).await?;
			}
			Ok(user)
		} else {
			Ok(None)
		}
	}

	pub fn from_config(email: &str) -> Option<User> {
		CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == email { Some(u.clone()) } else { None })
	}

	pub fn serialize<S: Serializer>(&self, ser: S) -> StdResult<S::Ok, S::Error> {
		ser.serialize_str(&self.email)
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> StdResult<Self, D::Error> {
		use serde::de::Error;
		let email = String::deserialize(de)?;
		CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == email { Some(u.clone()) } else { None })
			.ok_or(Error::custom("User not found"))
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
	use crate::tests::*;

	#[actix_web::test]
	async fn test_user() {
		let user = get_valid_user();

		assert!(user == user.email);
	}
}
