use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sqlx::{query, query_as, SqlitePool};

use crate::{CONFIG, RANDOM_STRING_LEN};

pub type Result<T> = std::result::Result<T, sqlx::Error>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
	pub username: Option<String>,
	pub realms: Vec<String>,
	pub email: String,
	pub name: Option<String>,
}

impl User {
	pub async fn from_session(db: &SqlitePool, session: actix_session::Session) -> Result<Option<User>> {
		if let Some(session_id) = session.get::<String>("session").unwrap_or(None) {
			User::from_session_id(db, session_id.as_str()).await
		} else {
			Ok(None)
		}
	}

	pub async fn from_session_id(db: &SqlitePool, session_id: &str) -> Result<Option<User>> {
		let session = UserSession::from_id(db, session_id).await?;
		if let Some(session) = session {
			let user = User::from_config(&session.email);
			if user.is_none() {
				session.delete(&db).await.unwrap();
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
}

impl PartialEq<String> for User {
	fn eq(&self, other: &String) -> bool {
		self.email == *other
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserSession {
	pub session_id: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl UserSession {
	pub async fn new(db: &SqlitePool, user: &User) -> Result<UserSession> {
		let expires_at = Utc::now().naive_utc().checked_add_signed(CONFIG.session_duration.to_owned()).unwrap();
		let record = UserSession {
			session_id: random_string(),
			email: user.email.clone(),
			expires_at,
		};

		query!(
				"INSERT INTO sessions (session_id, email, expires_at) VALUES (?, ?, ?)",
				record.session_id,
				record.email,
				record.expires_at
			)
			.execute(db)
			.await?;

		Ok(record)
	}

	pub async fn from_id(db: &SqlitePool, id: &str) -> Result<Option<UserSession>> {
		let session_res = query_as!(UserSession, "SELECT * FROM sessions WHERE session_id = ?", id)
			.fetch_optional(db)
			.await?;

		let session = if let Some(session) = session_res {
			session
		} else {
			return Ok(None)
		};

		if !session.is_expired(db).await? {
			Ok(Some(session))
		} else {
			Ok(None)
		}
	}

	pub async fn is_valid(&self, db: &SqlitePool) -> Result<bool> {
		let session_res = query_as!(UserSession, "SELECT * FROM sessions WHERE session_id = ?", self.session_id)
			.fetch_optional(db)
			.await?;

		let session = if let Some(session) = session_res {
			session
		} else {
			return Ok(false)
		};

		Ok(!self.is_expired(db).await? && self == &session)
	}

	pub async fn is_expired(&self, db: &SqlitePool) -> Result<bool> {
		if self.expires_at <= Utc::now().naive_utc() {
			query!("DELETE FROM sessions WHERE session_id = ?", self.session_id)
				.execute(db)
				.await?;

			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub async fn delete_id(db: &SqlitePool, id: &str) -> Result<()>{
		query!("DELETE FROM sessions WHERE session_id = ?", id)
			.execute(db)
			.await?;

		Ok(())
	}

	pub async fn delete(&self, db: &SqlitePool) -> Result<()> {
		UserSession::delete_id(db, &self.session_id).await
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserLink {
	pub magic: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl UserLink {
	pub async fn new(db: &SqlitePool, target: String) -> Result<UserLink> {
		let expires_at = Utc::now().naive_utc().checked_add_signed(CONFIG.link_duration.to_owned()).unwrap();
		let record = UserLink {
			magic: random_string(),
			email: target.clone(),
			expires_at,
		};

		query!(
				"INSERT INTO links (magic, email, expires_at) VALUES (?, ?, ?)",
				record.magic,
				record.email,
				record.expires_at
			)
			.execute(db)
			.await?;

		Ok(record)
	}

	pub async fn visit(db: &SqlitePool, target: String) -> Result<Option<User>> {
		let session = if let Some(link) = query_as!(UserLink, "SELECT * FROM links WHERE magic = ?", target)
			.fetch_optional(db)
			.await? {
				link
			} else {
				return Ok(None)
			};

		query!("DELETE FROM links WHERE magic = ?", target)
			.execute(db)
			.await?;

		if session.expires_at <= Utc::now().naive_utc() {
			return Ok(None)
		}

		Ok(
			CONFIG.users
				.iter()
				.find_map(|u| if u.email == session.email { Some(u.clone()) } else { None }))
	}
}

pub fn random_string() -> String {
	let mut rng = StdRng::from_entropy();
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rng.fill_bytes(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::*;
	use chrono::Utc;

	fn get_valid_user() -> User {
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == user_email { Some(u.clone()) } else { None })
			.unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	#[actix_web::test]
	async fn test_user() {
		let user = get_valid_user();

		assert!(user == user.email);
	}

	#[actix_web::test]
	async fn test_user_link() {
		let db = &db_connect().await;
		let user = get_valid_user();

		let link = UserLink::new(db, user.email.clone()).await.unwrap();

		assert_eq!(link.email, user.email);
		assert_eq!(link.magic.len(), RANDOM_STRING_LEN * 2);
		assert!(link.expires_at > Utc::now().naive_utc());

		// Test visit function
		let user_from_link = UserLink::visit(db, link.magic).await.unwrap().unwrap();
		assert_eq!(user, user_from_link);

		// Test expired UserLink
		let expired_target = "expired_magic".to_string();
		let expired_user_link = UserLink {
			magic: expired_target.clone(),
			email: "expired@example.com".to_string(),
			expires_at: Utc::now().naive_utc() - chrono::Duration::try_days(1).unwrap(),
		};

		query!("INSERT INTO links (magic, email, expires_at) VALUES (?, ?, ?)",
				expired_user_link.magic,
				expired_user_link.email,
				expired_user_link.expires_at
			)
			.execute(db)
			.await
			.unwrap();

		let expired_user = UserLink::visit(db, expired_target.clone()).await;
		assert!(expired_user.unwrap().is_none());

		// Make sure that the expired record is removed
		let record = query_as!(UserLink, "SELECT * FROM links WHERE magic = ?", expired_target)
			.fetch_optional(db)
			.await;
		assert!(record.unwrap().is_none());

		let expired_user = UserLink::visit(db, "nonexistent_magic".to_string()).await.unwrap();
		assert!(expired_user.is_none());
	}

	#[actix_web::test]
	async fn test_user_session() {
		let db = &db_connect().await;
		let user = get_valid_user();

		let session = UserSession::new(db, &user).await.unwrap();

		assert_eq!(session.email, user.email);
		assert_eq!(session.session_id.len(), RANDOM_STRING_LEN * 2);
		assert!(session.expires_at > Utc::now().naive_utc());
		println!("is_valid: {:?} session: {:?}", session.is_valid(db).await, session);
		assert!(session.is_valid(db).await.unwrap());
		assert!(!session.is_expired(db).await.unwrap());

		let session2 = UserSession::from_id(db, &session.session_id).await.unwrap().unwrap();
		assert_eq!(session, session2);

		let nonexistent_target = random_string();
		let session = UserSession::from_id(db, &nonexistent_target).await.unwrap();
		assert!(session.is_none());

		let expired_target = random_string();
		let expired_target2 = expired_target.clone();
		let expiry = Utc::now().naive_utc() - chrono::Duration::try_days(1).unwrap();
		query!("INSERT INTO sessions (session_id, email, expires_at) VALUES (?, ?, ?)",
				expired_target2,
				"expired@example.com",
				expiry,
			)
			.execute(db)
			.await
			.unwrap();
		let session = UserSession::from_id(db, "expired_session").await.unwrap();
		assert!(session.is_none());

		let record = query_as!(UserLink, "SELECT * FROM links WHERE magic = ?", expired_target)
			.fetch_optional(db)
			.await;
		assert!(record.unwrap().is_none());
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
