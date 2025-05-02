use std::marker::PhantomData;

use chrono::{NaiveDateTime, Utc};
use reindeer::{AsBytes, Db, Entity};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::user::User;
use crate::utils::random_string;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretString(String);

// Needed for reindeer
impl AsBytes for SecretString {
	fn as_bytes(&self) -> Vec<u8> { self.0.as_bytes().to_owned() }
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum EmptyMetadata {}

impl SecretString {
	pub fn new() -> Self {
		Self(random_string())
	}
}

impl From<String> for SecretString {
	fn from(s: String) -> Self {
		Self(s)
	}
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for SecretString {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

/// This trait describes any kind of user secret.
/// You can think of it as a "token" but I didn't use that term to avoid
/// confusion with all the other types of tokens.
pub trait UserSecretKind: PartialEq {
	const PREFIX: &'static str;
	type Metadata: Send + Sync + 'static;

	async fn duration() -> chrono::Duration;
}

#[derive(PartialEq, Serialize, Deserialize)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct UserSecret<K: UserSecretKind, M> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	code: SecretString,
	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	_kind: PhantomData<K>,
	/// The user it authenticates
	#[serde(with = "crate::user::as_string")]
	user: User,
	/// The time the token expires at
	expires_at: NaiveDateTime,
	/// Metadata related to the secret - could be anything to nothing
	pub metadata: M,
}

impl<K: UserSecretKind, M: Serialize + DeserializeOwned> Entity for UserSecret<K, M> {
	type Key=SecretString;

	fn store_name() -> &'static str { K::PREFIX }
	fn get_key(&self) -> &Self::Key { &self.code }
	fn set_key(&mut self, key: &Self::Key) { self.code = key.clone(); }
}

impl<K: UserSecretKind, M: Serialize + DeserializeOwned + PartialEq> UserSecret<K, M> {
	pub async fn new(db: &Db, user: User, metadata: M) -> Result<Self> {
		let expires_at = chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(K::duration().await)
			.expect(format!("Couldn't generate expiry for {}", K::PREFIX).as_str());

		let token = Self {
			code: SecretString::new(),
			_kind: PhantomData,
			user,
			expires_at,
			metadata,
		};

		token.save(db)?;

		Ok(token)
	}

	pub async fn is_expired(&self, db: &Db) -> Result<bool> {
		if self.expires_at <= Utc::now().naive_utc() {
			Self::remove(&self.code, db)?;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub async fn is_valid(&self, db: &Db) -> Result<bool> {
		// Make sure that the secret still exists in the database
		if Self::exists(&self.code, db)? {
			return Ok(false);
		}

		// Check if the secret is expired
		if self.is_expired(db).await? {
			return Ok(false);
		}

		Ok(true)
	}

	pub async fn from_string(db: &Db, code: String) -> Result<Self> {
		let token = Self::get(&code.into(), db)?.ok_or(AppErrorKind::TokenNotFound)?;

		// Can't call is_valid as async recursion is not allowed
		let is_valid = token.is_valid(db).await?;

		if !is_valid {
			Err(AppErrorKind::TokenNotFound.into())
		} else {
			Ok(token)
		}
	}
}
