use std::marker::PhantomData;

use actix_session::Session;
use actix_web::http::Uri;
use actix_web::HttpRequest;
use chrono::{NaiveDateTime, Utc};
use log::{info, warn};
use reindeer::{Db, Entity};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::user::User;
use crate::utils::{get_request_origin, random_string};
use crate::{PROXIED_COOKIE, SCOPED_SESSION_COOKIE, SESSION_COOKIE};

#[allow(async_fn_in_trait)]
pub trait TokenKindType:
	std::fmt::Debug
	+ Clone
	+ PartialEq
	+ Eq
	+ PartialOrd
	+ Ord
	+ Serialize
	+ DeserializeOwned
	+ Send
	+ Sync
	+ Unpin
{
	const NAME: &'static str;
	const EPHEMERAL: bool;
	type BoundType: TokenKindType;

	async fn get_duration() -> chrono::Duration;

	async fn get_expiry() -> NaiveDateTime {
		chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(Self::get_duration().await)
			.expect(format!("Couldn't generate expiry for {:?}", Self::NAME).as_str())
	}
}

macro_rules! token_kind {
	{$($name:ident(duration = $duration:expr, ephemeral = $ephemeral:expr, bound_type = $bound_type:tt),)*} => {
		$(
			pub type $name = Token<token_kind::$name>;
		)*

		pub fn register_token_kind(db: &reindeer::Db) -> reindeer::Result<()> {
			$(
				$name::register(db)?;
			)*

			Ok(())
		}

		mod token_kind {
			use super::*;

			$(
				#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
				pub struct $name;

				impl TokenKindType for $name {
					const NAME: &'static str = stringify!($name);
					const EPHEMERAL: bool = $ephemeral;
					type BoundType = $bound_type;

					async fn get_duration() -> chrono::Duration { $duration }
				}
			)*
		}
	};
}

#[derive(Entity, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[entity(name = "token", id = "code", version = 1)]
// #[siblings(("token", BreakLink))]
#[non_exhaustive]
pub struct Token<K: TokenKindType> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	pub code: String,
	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	_kind: PhantomData<K>,
	/// The user it authenticates
	#[serde(with = "crate::user::as_string")]
	pub user: User,
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
	pub async fn is_expired(&self, db: &Db) -> Result<bool> {
		if self.expires_at <= Utc::now().naive_utc() {
			self.delete(db).await?;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub async fn is_valid(&self, db: &Db) -> Result<bool> {
		if self.is_expired(db).await? {
			return Ok(false);
		}

		let other = Self::from_code(db, &self.code).await?;
		let result = self == &other;

		if let Ok(parent) = self.get_parent(db).await {
			// Can't call parent's is_valid as async recursion is not allowed
			Ok(result && !parent.is_expired(db).await?)
		} else {
			Ok(result)
		}
	}

	pub async fn get_parent(&self, db: &Db) -> Result<Self> {
		let code = self.bound_to.as_ref().ok_or(AppErrorKind::NoParentToken)?;
		Self::from_code(db, code).await
	}

	pub async fn from_code(db: &Db, code: &String) -> Result<Self> {
		let token = Self::get(code, &db)?.ok_or(AppErrorKind::TokenNotFound)?;

		// Can't call is_valid as async recursion is not allowed
		let is_expired = token.is_expired(db).await?;

		if K::EPHEMERAL || is_expired {
			token.delete(db).await?;
		}

		if is_expired {
			return Err(AppErrorKind::TokenNotFound.into());
		}

		Ok(token)
	}

	pub async fn new(
		db: &Db,
		user: User,
		bound_to: Option<String>,
		metadata: Option<String>,
	) -> Result<Self> {
		let expires_at = if let Some(bound_code) = &bound_to {
			let bound_token: Token<K::BoundType> = Token::from_code(db, &bound_code).await?;

			if !bound_token.is_valid(db).await? {
				return Err(AppErrorKind::InvalidParentToken.into());
			}

			bound_token.expires_at
		} else {
			K::get_expiry().await
		};

		let token = Self {
			code: random_string(),
			_kind: PhantomData,
			user: user,
			expires_at,
			bound_to,
			metadata: metadata,
		};

		token.save(db)?;

		Ok(token)
	}

	pub async fn delete(&self, db: &Db) -> Result<()> {
		let now = Utc::now().naive_utc();
		let code = self.code.clone();
		let code_opt = Some(self.code.clone());

		// TODO: Use link & cascade instead
		Self::filter_remove(
			|t| t.code == code || t.bound_to == code_opt || t.expires_at <= now,
			&db,
		)?;

		Ok(())
	}
}

// TODO: The bound type should be absent instead of Self
token_kind! {
	MagicLinkToken(duration = crate::CONFIG.read().await.link_duration, ephemeral = true, bound_type = Self),
	SessionToken(duration = crate::CONFIG.read().await.session_duration, ephemeral = false, bound_type = Self),
	ProxyCookieToken(duration = crate::CONFIG.read().await.oidc_code_duration, ephemeral = true, bound_type = SessionToken),
	ScopedSessionToken(duration = crate::CONFIG.read().await.session_duration, ephemeral = false, bound_type = SessionToken),
	OIDCCodeToken(duration = crate::CONFIG.read().await.oidc_code_duration, ephemeral = true, bound_type = SessionToken),
	OIDCBearerToken(duration = crate::CONFIG.read().await.session_duration, ephemeral = false, bound_type = Self),
	WebauthnToken(duration = crate::CONFIG.read().await.oidc_code_duration, ephemeral = true, bound_type = SessionToken),
}

impl SessionToken {
	pub async fn from_session(db: &Db, session: &Session) -> Result<Self> {
		if let Some(session_id) = session.get::<String>(SESSION_COOKIE).unwrap_or(None) {
			let token = Self::from_code(db, &session_id).await;

			if token.is_err() {
				session.remove(SESSION_COOKIE);
			}

			token
		} else {
			Err(AppErrorKind::TokenNotFound.into())
		}
	}
}

impl ScopedSessionToken {
	pub async fn from_session(db: &Db, req: &HttpRequest) -> Result<Option<Self>> {
		let origin = get_request_origin(req)?;

		if let Some(session_id) = req.cookie(SCOPED_SESSION_COOKIE) {
			let token = ScopedSessionToken::from_code(db, &session_id.value().to_string()).await?;
			let metadata = token.metadata.clone().unwrap_or_default();
			let scope_parsed = metadata
				.parse::<Uri>()
				.map_err(|_| AppErrorKind::InvalidRedirectUri)?;
			let scope_scheme = scope_parsed
				.scheme_str()
				.ok_or(AppErrorKind::InvalidRedirectUri)?;
			let scope_authority = scope_parsed
				.authority()
				.ok_or(AppErrorKind::InvalidRedirectUri)?;
			let scope_origin = format!("{}://{}", scope_scheme, scope_authority);

			if origin == scope_origin {
				return Ok(Some(token));
			}

			warn!(
				"Invalid scope for scoped session: {} vs {}",
				origin, scope_origin
			);
		}

		Ok(None)
	}
}

impl ScopedSessionToken {
	pub async fn from_proxy_cookie(db: &Db, req: &actix_web::HttpRequest) -> Result<Option<Self>> {
		let cookie = req
			.cookie(PROXIED_COOKIE)
			.ok_or(AppErrorKind::MissingCookieHeader)?;

		let code = cookie.value().to_string();
		let token = ProxyCookieToken::from_code(db, &code).await?;
		let metadata = token.metadata.clone().unwrap_or_default();
		let scope_parsed = metadata
			.parse::<Uri>()
			.map_err(|_| AppErrorKind::InvalidRedirectUri)?;
		let scope_scheme = scope_parsed
			.scheme_str()
			.ok_or(AppErrorKind::InvalidRedirectUri)?;
		let scope_authority = scope_parsed
			.authority()
			.ok_or(AppErrorKind::InvalidRedirectUri)?;
		let scope_origin = format!("{}://{}", scope_scheme, scope_authority);
		let origin = get_request_origin(req)?;

		if origin != scope_origin {
			warn!(
				"Invalid scope for proxy cookie: {} vs {}",
				&origin, &scope_origin
			);
			return Ok(None);
		}

		let scoped_session =
			ScopedSessionToken::new(db, token.user, token.bound_to.clone(), Some(scope_origin))
				.await?;
		info!("New scoped session for: {}", &origin);

		Ok(Some(scoped_session))
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
		let user = get_valid_user().await;

		let link = MagicLinkToken::new(db, user.clone(), None, None)
			.await
			.unwrap();

		assert_eq!(link.user, user.email);
		assert_eq!(link.code.len(), RANDOM_STRING_LEN * 2);
		assert!(link.expires_at > Utc::now().naive_utc());

		// Test visit function
		let user_from_link = MagicLinkToken::from_code(db, &link.code)
			.await
			.unwrap()
			.user;
		assert_eq!(user, user_from_link);

		// Test expired UserLink
		let expired_target = "expired_magic".to_string();
		let expired_user_link = MagicLinkToken {
			code: expired_target.clone(),
			_kind: PhantomData,
			user: user,
			expires_at: Utc::now().naive_utc() - chrono::Duration::try_days(2).unwrap(),
			bound_to: None,
			metadata: None,
		};

		expired_user_link.save(db).unwrap();

		let expired_user = MagicLinkToken::from_code(db, &expired_target).await;
		assert!(expired_user.is_err());

		// Make sure that the expired record is removed
		let record = MagicLinkToken::get(&expired_target, db).unwrap();
		println!("{:?}", record);
		assert!(record.is_none());

		let expired_user = MagicLinkToken::from_code(db, &"nonexistent_magic".to_string()).await;
		assert!(expired_user.is_err());
	}
}
