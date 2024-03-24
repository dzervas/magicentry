use actix_session::Session;
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as, SqlitePool};

use crate::user::User;
use crate::utils::random_string;
use crate::{CONFIG, SESSION_COOKIE};
use crate::error::{AppErrorKind, Result};

#[derive(sqlx::Type, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[sqlx(rename_all = "lowercase")]
pub enum TokenKind {
	/// Magic link token sent to the user to log in (one-time use)
	MagicLink,
	/// Cookie session token
	Session,
	/// Cookie session token sent to the application proxy to authenticate the user (one-time use, it's exchanged for a `ScopedSession` by us)
	ProxyCookie,
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
			TokenKind::MagicLink => CONFIG.link_duration.to_owned(),
			TokenKind::Session |
			TokenKind::ScopedSession |
			TokenKind::OIDCBearer => CONFIG.session_duration.to_owned(),
			TokenKind::OIDCCode |
			TokenKind::ProxyCookie => CONFIG.oidc_code_duration.to_owned(),
		};

		Utc::now()
			.naive_utc()
			.checked_add_signed(duration)
			.expect(format!("Couldn't generate expiry for {:?}", self).as_str())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
// NOTE: Would be nice to have generics over the TokenKind
pub struct Token {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	pub code: String,
	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	pub kind: TokenKind,
	/// The user it authenticates
	// NOTE: This would be nice to be a concrete User
	pub user: String,
	/// The time the token expires
	pub expires_at: NaiveDateTime,
	/// The parent token it's bound to (if any) - e.g. a `ScopedSession` is bound to a `Session`.
	/// It describes that the longevity of the child can never exceed the parent
	/// while limiting the scope of the child to the parent.
	// NOTE: This would be nice to be a concrete Token
	pub bound_to: Option<String>,
	// NOTE: This would be nice to be a generic
	pub metadata: Option<String>,
}

impl Token {
	/// Describes if the token is ephemeral and should be deleted after the first use
	pub fn is_ephemeral(&self) -> bool {
		match self.kind {
			TokenKind::MagicLink |
			TokenKind::OIDCCode => true,
			_ => false,

		}
	}

	pub async fn is_expired(&self, db: &SqlitePool) -> Result<bool> {
		if self.expires_at <= Utc::now().naive_utc() {
			self.delete(db).await?;
			Ok(false)
		} else {
			Ok(true)
		}
	}

	pub async fn is_valid(&self, db: &SqlitePool) -> Result<bool> {
		if self.is_expired(db).await? {
			return Ok(false)
		}

		let other = Self::from_code_unchecked(db, &self.code).await?;
		// TODO: Check expiry and user against the parent

		Ok(self == &other && self.get_user().is_some())
	}

	pub fn get_user(&self) -> Option<User> {
		User::from_config(&self.user)
	}

	pub async fn get_parent(&self, db: &SqlitePool) -> Result<Self> {
		let code = self.bound_to.as_ref().ok_or(AppErrorKind::NoParentToken)?;
		Self::from_code_unchecked(db, code).await
	}

	async fn from_code_unchecked(db: &SqlitePool, code: &str) -> Result<Self> {
		let token = query_as!(Token, r#"SELECT
			code,
			kind AS "kind: TokenKind",
			user,
			expires_at,
			bound_to,
			metadata
			FROM tokens WHERE code = ?"#, code)
			.fetch_optional(db)
			.await?
			.ok_or(AppErrorKind::TokenNotFound)?;

		let is_expired = token.is_expired(db).await?;

		if token.is_ephemeral() || !is_expired || token.get_user().is_none() {
			token.delete(db).await?;
		}

		if !is_expired {
			return Err(AppErrorKind::TokenNotFound.into());
		}

		Ok(token)
	}

	pub async fn from_code(db: &SqlitePool, code: &str, kind: TokenKind) -> Result<Self> {
		let token = Self::from_code_unchecked(db, code).await?;
		if token.kind != kind {
			return Err(AppErrorKind::TokenNotFound.into());
		}
		Ok(token)
	}

	pub async fn new(db: &SqlitePool, kind: TokenKind, user: &User, bound_to: Option<String>, metadata: Option<String>) -> Result<Self> {
		let expires_at = if let Some(bound_code) = &bound_to {
			let bound_token = Self::from_code_unchecked(db, &bound_code).await?;
			bound_token.expires_at
		} else {
			kind.get_expiry()
		};

		let token = Token {
			code: random_string(),
			kind,
			user: user.email.clone(),
			expires_at,
			bound_to,
			metadata: metadata,
		};

		query!(
				"INSERT INTO tokens (code, kind, user, expires_at, bound_to, metadata) VALUES (?, ?, ?, ?, ?, ?)",
				token.code,
				token.kind,
				token.user,
				token.expires_at,
				token.bound_to,
				token.metadata
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

	pub async fn from_session(db: &SqlitePool, session: &Session) -> Result<Self> {
		if let Some(session_id) = session.get::<String>(SESSION_COOKIE).unwrap_or(None) {
			Self::from_code(db, session_id.as_str(), TokenKind::Session).await
		} else {
			#[cfg(debug_assertions)]
			log::debug!("No session found in the session cookie");
			// TODO: This doesn't make sense
			session.remove(SESSION_COOKIE);
			Err(AppErrorKind::NoSessionSet.into())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;
	use crate::RANDOM_STRING_LEN;
	use chrono::Utc;

	#[actix_web::test]
	async fn test_token() {
		let db = &db_connect().await;
		let user = get_valid_user();

		let link = Token::new(db, TokenKind::MagicLink, &user, None, None).await.unwrap();

		assert_eq!(link.user, user.email);
		assert_eq!(link.code.len(), RANDOM_STRING_LEN * 2);
		assert!(link.expires_at > Utc::now().naive_utc());

		// Test visit function
		let user_from_link = Token::from_code(db, &link.code, TokenKind::MagicLink).await.unwrap().get_user().unwrap();
		assert_eq!(user, user_from_link);

		// Test expired UserLink
		let expired_target = "expired_magic";
		let expired_user_link = Token {
			code: expired_target.to_string(),
			kind: TokenKind::MagicLink,
			user: "expired@example.com".to_string(),
			expires_at: Utc::now().naive_utc() - chrono::Duration::try_days(1).unwrap(),
			bound_to: None,
			metadata: None,
		};

		query!("INSERT INTO tokens (code, kind, user, expires_at) VALUES (?, ?, ?, ?)",
				expired_user_link.code,
				TokenKind::MagicLink,
				expired_user_link.user,
				expired_user_link.expires_at
			)
			.execute(db)
			.await
			.unwrap();

		let expired_user = Token::from_code(db, expired_target, TokenKind::MagicLink).await;
		assert!(expired_user.is_err());

		// Make sure that the expired record is removed
		let record = query_as!(Token, r#"SELECT
			code,
			kind AS "kind: TokenKind",
			user,
			expires_at,
			bound_to,
			metadata
			FROM tokens WHERE code = ?"#, expired_target)
			.fetch_optional(db)
			.await;
		assert!(record.unwrap().is_none());

		let expired_user = Token::from_code(db, "nonexistent_magic", TokenKind::MagicLink).await;
		assert!(expired_user.is_err());
	}
}
