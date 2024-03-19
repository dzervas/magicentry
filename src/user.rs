use std::result::Result as StdResult;

use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{query, query_as, SqlitePool};

use crate::utils::random_string;
use crate::{CONFIG, SESSION_COOKIE};
use crate::error::{AppErrorKind, Result};

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
		let session = Token::from_code(db, session_id).await;
		if let Ok(Some(session)) = session {
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

#[derive(sqlx::Type, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[sqlx(rename_all = "lowercase")]
pub enum TokenKind {
	/// Magic link token sent to the user to log in (one-time use)
	Magic,
	/// Cookie session token
	Session,
	/// Cookie session token sent to the application proxy to authenticate the user (one-time use, it's exchanged for a `ScopedSession` by us)
	AuthProxy,
	/// Cookie session token that authenticates a user against a specific scope - it's bound to a `Session` and both are deleted on logout
	ScopedSession,
	/// OIDC code sent to the client during authorize using the redirect_uri (one-time use)
	OIDCCode,
	/// OIDC Bearer token sent to the client after the client has exchanged the OIDC code for a token
	OIDCBearer,
}

impl TokenKind {
	pub fn get_expiry(&self) -> NaiveDateTime {
		let duration = match self {
			TokenKind::Magic => CONFIG.link_duration.to_owned(),
			TokenKind::Session |
			TokenKind::ScopedSession |
			TokenKind::OIDCBearer => CONFIG.session_duration.to_owned(),
			TokenKind::OIDCCode |
			TokenKind::AuthProxy => CONFIG.oidc_code_duration.to_owned(),
		};

		Utc::now()
			.naive_utc()
			.checked_add_signed(duration)
			.expect(format!("Couldn't generate expiry for {:?}", self).as_str())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	pub code: String,
	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	pub kind: TokenKind,
	/// The user it authenticates
	pub user: String,
	/// The time the token expires
	pub expires_at: NaiveDateTime,
	/// The parent token it's bound to (if any) - e.g. a `ScopedSession` is bound to a `Session`.
	/// It describes that the longevity of the child can never exceed the parent
	/// while limiting the scope of the child to the parent.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub bound_to: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub metadata: Option<String>,
}

impl Token {
	/// Describes if the token is ephemeral and should be deleted after the first use
	pub fn is_ephemeral(&self) -> bool {
		match self.kind {
			TokenKind::Magic |
			TokenKind::OIDCCode |
			TokenKind::ScopedSession => true,
			_ => false,

		}
	}

	pub async fn is_valid(&self, db: &SqlitePool) -> Result<bool> {
		if self.expires_at <= Utc::now().naive_utc() {
			self.delete(db).await?;
			return Ok(false)
		}

		let other = Self::from_code(db, &self.code).await?;

		if let Some(record) = other {
			Ok(self == &record)
		} else {
			Ok(false)
		}
	}

	pub fn get_user(&self) -> Option<User> {
		User::from_config(&self.user)
	}

	pub async fn get_parent(&self, db: &SqlitePool) -> Result<Option<Self>> {
		let code = self.bound_to.as_ref().ok_or(AppErrorKind::NoParentToken)?;
		Self::from_code(db, code).await
	}

	pub async fn from_code(db: &SqlitePool, code: &str) -> Result<Option<Self>> {
		let token = query_as!(Token, r#"SELECT
			code,
			kind AS "kind: TokenKind",
			user,
			expires_at,
			bound_to,
			metadata
			FROM tokens WHERE code = ?"#, code)
			.fetch_optional(db)
			.await?;

		if let Some(record) = &token {
			if record.is_ephemeral() {
				record.delete(db).await?;
			}
		}

		Ok(token)
	}

	pub async fn generate(db: &SqlitePool, kind: TokenKind, user: &User, bound_to: Option<&Self>) -> Result<Self> {
		let expires_at = if let Some(bound_token) = bound_to {
			bound_token.expires_at
		} else {
			kind.get_expiry()
		};

		let token = Token {
			code: random_string(),
			kind,
			user: user.email.clone(),
			expires_at,
			bound_to: bound_to.map(|b| b.code.clone()),
			metadata: None,
		};

		query!(
				"INSERT INTO tokens (code, kind, user, expires_at, bound_to) VALUES (?, ?, ?, ?, ?)",
				token.code,
				token.kind,
				token.user,
				token.expires_at,
				token.bound_to
			)
			.execute(db)
			.await?;

		Ok(token)
	}

	pub async fn delete(&self, db: &SqlitePool) -> Result<()> {
		let now = Utc::now().naive_utc();
		query!(
				"DELETE FROM tokens WHERE code = ? OR bound_to = ? OR expires_at <= ?",
				self.code,
				self.code,
				now
			)
			.execute(db)
			.await?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::*;
	use crate::RANDOM_STRING_LEN;
	use chrono::Utc;

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
}
