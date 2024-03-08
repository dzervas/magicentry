use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sqlx::{query, query_as, SqlitePool};

use crate::{CONFIG, LINK_DURATION, RANDOM_STRING_LEN, SESSION_DURATION};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct User {
	pub email: String,
	pub realms: Vec<String>,
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
	pub async fn new(db: &SqlitePool, user: &User) -> Result<UserSession, sqlx::Error> {
		let expires_at = Utc::now().naive_utc().checked_add_signed(SESSION_DURATION.to_owned()).unwrap();
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

	pub async fn from_id(db: &SqlitePool, id: &str) -> Option<UserSession> {
		let session_res = query_as!(UserSession, "SELECT * FROM sessions WHERE session_id = ?", id)
			.fetch_one(db)
			.await;

		let session = if let Ok(session) = session_res {
			session
		} else {
			return None
		};

		if !session.is_expired(db).await {
			Some(session)
		} else {
			None
		}
	}

	pub async fn is_valid(&self, db: &SqlitePool) -> bool {
		let session_res = query_as!(UserSession, "SELECT * FROM sessions WHERE session_id = ?", self.session_id)
			.fetch_one(db)
			.await;

		let session = if let Ok(session) = session_res {
			session
		} else {
			return false
		};

		!self.is_expired(db).await && self == &session
	}

	pub async fn is_expired(&self, db: &SqlitePool) -> bool {
		if self.expires_at <= Utc::now().naive_utc() {
			query!("DELETE FROM sessions WHERE session_id = ?", self.session_id)
				.execute(db)
				.await
				.unwrap();

			false
		} else {
			true
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserLink {
	pub magic: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl UserLink {
	pub async fn new(db: &SqlitePool, target: String) -> UserLink {
		let expires_at = Utc::now().naive_utc().checked_add_signed(LINK_DURATION.to_owned()).unwrap();
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
			.await
			.unwrap();

		record
	}

	pub async fn visit(db: &SqlitePool, target: String) -> Option<User> {
		let record = if let Ok(link) = query_as!(UserLink, "SELECT * FROM links WHERE magic = ?", target)
			.fetch_one(db)
			.await {
				link
			} else {
				return None
			};

		if record.expires_at <= Utc::now().naive_utc() {
			query!("DELETE FROM links WHERE magic = ?", target)
				.execute(db)
				.await
				.unwrap();

			return None
		}

		CONFIG.users.iter().find_map(|u| if u.email == record.email { Some(u.clone()) } else { None })
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
	use crate::tests::DB_POOL;

use super::*;
	use chrono::Utc;

	fn get_valid_user() -> User {
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string(), "realm".to_string()];
		let user = CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == user_email { Some(u.clone()) } else { None })
			.unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	#[test]
	fn test_userlink() {
		let conn = &mut DB_POOL.get().unwrap();
		let user = get_valid_user();

		let link = UserLink::new(conn, user.email.clone());

		assert_eq!(link.email, user.email);
		assert_eq!(link.magic.len(), RANDOM_STRING_LEN * 2);
		assert!(link.expires_at > Utc::now().naive_utc());

		// Test visit function
		let user_from_link = UserLink::visit(conn, link.magic).unwrap();
		assert_eq!(user, user_from_link);

		// Test expired UserLink
		let expired_target = "expired_magic".to_string();
		let expired_user_link = UserLink {
			magic: expired_target.clone(),
			email: "expired@example.com".to_string(),
			expires_at: Utc::now().naive_utc() - chrono::Duration::try_days(1).unwrap(),
		};

		diesel::insert_into(crate::schema::links::table)
			.values(&expired_user_link)
			.execute(conn)
			.unwrap();

		let expired_user = UserLink::visit(conn, expired_target.clone());
		assert!(expired_user.is_none());

		// Make sure that the expired record is removed
		use crate::schema::links::dsl::*;
		let record = links
			.filter(magic.eq(expired_target.clone()))
			.first::<UserLink>(conn);

		assert!(record.is_err());

		let expired_user = UserLink::visit(conn, "nonexistent_magic".to_string());
		assert!(expired_user.is_none());
	}

	#[test]
	fn test_usersession() {
		let conn = &mut DB_POOL.get().unwrap();
		let user = get_valid_user();

		let session = UserSession::new(conn, &user);

		assert_eq!(session.email, user.email);
		assert_eq!(session.session_id.len(), RANDOM_STRING_LEN * 2);
		assert!(session.expires_at > Utc::now().naive_utc());
		assert!(session.is_valid(conn));
		assert!(!session.is_expired(conn));

		let session2 = UserSession::from_id(conn, &session.session_id).unwrap();
		assert_eq!(session, session2);
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
