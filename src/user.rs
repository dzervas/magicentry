use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::{CONFIG, RANDOM_STRING_LEN};

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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Insertable, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::sessions)]
pub struct UserSession {
	pub session_id: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl UserSession {
	pub fn new(conn: &mut crate::DbConn, user: &User) -> UserSession {
		let record = UserSession {
			session_id: random_string(),
			email: user.email.clone(),
			expires_at: Utc::now().naive_utc(),
		};

		diesel::insert_into(crate::schema::sessions::table)
			.values(&record)
			.execute(conn)
			.unwrap();

		record
	}

	pub fn from_id(conn: &mut crate::DbConn, id: &str) -> Option<UserSession> {
		use crate::schema::sessions::dsl::*;

		let session = if let Ok(session) = sessions
			.filter(session_id.eq(id.to_string()))
			.first::<UserSession>(conn) {
				session
			} else {
				return None
			};

		if !session.is_expired(conn) {
			Some(session)
		} else {
			None
		}
	}

	pub fn is_valid(&self, conn: &mut crate::DbConn) -> bool {
		use crate::schema::sessions::dsl::*;

		let session = if let Ok(session) = sessions
			.filter(session_id.eq(self.session_id.clone()))
			.first::<UserSession>(conn) {
				session
			} else {
				return false
			};

		!self.is_expired(conn) && self == &session
	}

	pub fn is_expired(&self, conn: &mut crate::DbConn) -> bool {
		use crate::schema::sessions::dsl::*;

		if self.expires_at <= Utc::now().naive_utc() {
			diesel::delete(sessions.filter(session_id.eq(self.session_id.clone())))
				.execute(conn)
				.unwrap();

			false
		} else {
			true
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::links)]
pub struct UserLink {
	pub magic: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl UserLink {
	pub fn new(conn: &mut crate::DbConn, user: &User) -> UserLink {
		let record = UserLink {
			magic: random_string(),
			email: user.email.clone(),
			expires_at: Utc::now().naive_utc(),
		};

		diesel::insert_into(crate::schema::links::table)
			.values(&record)
			.execute(conn)
			.unwrap();

		record
	}

	pub fn visit(conn: &mut crate::DbConn, target: String) -> Option<User> {
		use crate::schema::links::dsl::*;

		let record = if let Ok(link) = links
			.filter(magic.eq(target.clone()))
			.first::<UserLink>(conn) {
				link
			} else {
				return None
			};

		if record.expires_at <= Utc::now().naive_utc() {
			diesel::delete(links.filter(magic.eq(target)))
				.execute(conn)
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
