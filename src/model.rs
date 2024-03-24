use std::marker::PhantomData;

use actix_session::Session;
use chrono::{NaiveDateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use sqlx::{query, SqlitePool};

use crate::user::User;
use crate::utils::random_string;
use crate::SESSION_COOKIE;
use crate::error::{AppErrorKind, Result};

pub trait TokenKindType: std::fmt::Debug + Clone + PartialEq + Eq + PartialOrd + Ord + Serialize + DeserializeOwned + Send + Sync + Unpin {
	const NAME: &'static str;
	const EPHEMERAL: bool;
	type BoundType: TokenKindType;

	fn get_duration() -> chrono::Duration;

	fn get_expiry() -> NaiveDateTime {
		chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(Self::get_duration())
			.expect(format!("Couldn't generate expiry for {:?}", Self::NAME).as_str())

	}
}

macro_rules! token_kind {
	{$($name:ident(duration = $duration:expr, ephemeral = $ephemeral:expr, bound_type = $bound_type:tt),)*} => {
		$(
			pub type $name = Token<token_kind::$name>;
		)*

		mod token_kind {
			use super::*;

			$(
				#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
				pub struct $name;

				impl TokenKindType for $name {
					const NAME: &'static str = stringify!($name);
					const EPHEMERAL: bool = $ephemeral;
					type BoundType = $bound_type;

					fn get_duration() -> chrono::Duration { $duration }
				}
			)*
		}
	};
}

// TODO: The bound type should be absent instead of Self
token_kind! {
	MagicLinkToken(duration = crate::CONFIG.link_duration, ephemeral = true, bound_type = Self),
	SessionToken(duration = crate::CONFIG.session_duration, ephemeral = false, bound_type = Self),
	ProxyCookieToken(duration = crate::CONFIG.oidc_code_duration, ephemeral = true, bound_type = SessionToken),
	ScopedSessionToken(duration = crate::CONFIG.session_duration, ephemeral = false, bound_type = SessionToken),
	OIDCCodeToken(duration = crate::CONFIG.oidc_code_duration, ephemeral = true, bound_type = SessionToken),
	OIDCBearerToken(duration = crate::CONFIG.session_duration, ephemeral = false, bound_type = Self),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, FromRow)]
#[non_exhaustive]
pub struct Token<K: TokenKindType> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	pub code: String,
	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	#[sqlx(skip)]
	_kind: PhantomData<K>,
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
	// TODO: make the metadata a non-exhaustive struct
	pub metadata: Option<String>,
}

impl<K: TokenKindType> Token<K> {
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

		let other = Self::from_code(db, &self.code).await?;
		// TODO: Check expiry and user against the parent

		Ok(self == &other && self.get_user().is_some())
	}

	pub fn get_user(&self) -> Option<User> {
		User::from_config(&self.user)
	}

	pub async fn get_parent(&self, db: &SqlitePool) -> Result<Self> {
		let code = self.bound_to.as_ref().ok_or(AppErrorKind::NoParentToken)?;
		Self::from_code(db, code).await
	}

	pub async fn from_code(db: &SqlitePool, code: &str) -> Result<Self> {
		let token: Self = sqlx::query_as(r#"SELECT
			code,
			user,
			expires_at,
			bound_to,
			metadata
			FROM tokens WHERE code = ? AND kind = ?"#)
			.bind(code)
			.bind(K::NAME)
			.fetch_optional(db)
			.await?
			.ok_or(AppErrorKind::TokenNotFound)?;

		let is_expired = token.is_expired(db).await?;

		if K::EPHEMERAL || !is_expired || token.get_user().is_none() {
			token.delete(db).await?;
		}

		if !is_expired {
			return Err(AppErrorKind::TokenNotFound.into());
		}

		Ok(token)
	}

	pub async fn new(db: &SqlitePool, user: &User, bound_to: Option<String>, metadata: Option<String>) -> Result<Self> {
		let expires_at = if let Some(bound_code) = &bound_to {
			// TODO: Force check the bound if it's valid
			let bound_token: Token<K::BoundType> = Token::from_code(db, &bound_code).await?;
			bound_token.expires_at
		} else {
			K::get_expiry()
		};

		let token = Self {
			code: random_string(),
			_kind: PhantomData,
			user: user.email.clone(),
			expires_at,
			bound_to,
			metadata: metadata,
		};

		sqlx::query("INSERT INTO tokens (code, kind, user, expires_at, bound_to, metadata) VALUES (?, ?, ?, ?, ?, ?)")
			.bind(&token.code)
			.bind(K::NAME)
			.bind(&token.user)
			.bind(&token.expires_at)
			.bind(&token.bound_to)
			.bind(&token.metadata)
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

impl SessionToken {
	pub async fn from_session(db: &SqlitePool, session: &Session) -> Result<Self> {
		if let Some(session_id) = session.get::<String>(SESSION_COOKIE).unwrap_or(None) {
			Self::from_code(db, session_id.as_str()).await
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
	use tests::MagicLinkToken;

	#[actix_web::test]
	async fn test_token() {
		let db = &db_connect().await;
		let user = get_valid_user();

		let link = MagicLinkToken::new(db, &user, None, None).await.unwrap();

		assert_eq!(link.user, user.email);
		assert_eq!(link.code.len(), RANDOM_STRING_LEN * 2);
		assert!(link.expires_at > Utc::now().naive_utc());

		// Test visit function
		let user_from_link = MagicLinkToken::from_code(db, &link.code).await.unwrap().get_user().unwrap();
		assert_eq!(user, user_from_link);

		// Test expired UserLink
		let expired_target = "expired_magic";
		let expired_user_link = MagicLinkToken {
			code: expired_target.to_string(),
			_kind: PhantomData,
			user: "expired@example.com".to_string(),
			expires_at: Utc::now().naive_utc() - chrono::Duration::try_days(1).unwrap(),
			bound_to: None,
			metadata: None,
		};

		sqlx::query("INSERT INTO tokens (code, kind, user, expires_at) VALUES (?, ?, ?, ?)")
			.bind(expired_user_link.code)
			.bind(token_kind::MagicLinkToken::NAME)
			.bind(expired_user_link.user)
			.bind(expired_user_link.expires_at)
			.execute(db)
			.await
			.unwrap();

		let expired_user = MagicLinkToken::from_code(db, expired_target).await;
		assert!(expired_user.is_err());

		// Make sure that the expired record is removed
		let record = sqlx::query_as::<_, MagicLinkToken>(r#"SELECT
			code,
			user,
			expires_at,
			bound_to,
			metadata
			FROM tokens WHERE code = ?"#)
			.bind(expired_target)
			.fetch_optional(db)
			.await;
		assert!(record.unwrap().is_none());

		let expired_user = MagicLinkToken::from_code(db, "nonexistent_magic").await;
		assert!(expired_user.is_err());
	}
}
