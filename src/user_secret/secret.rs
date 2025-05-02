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
pub enum EmptyMetadata { Instance }

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
struct InternalUserSecret<K: UserSecretKind, M> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	code: SecretString,
	/// The user it authenticates
	#[serde(with = "crate::user::as_string")]
	user: User,
	/// The time the token expires at
	expires_at: NaiveDateTime,
	/// Metadata related to the secret - could be anything to nothing
	metadata: M,

	/// The type of token - used to determine how to handle the token (ephemeral, relation to parent token, etc.)
	_kind: PhantomData<K>,
}

impl<K: UserSecretKind, M: Serialize + DeserializeOwned> Entity for InternalUserSecret<K, M> {
	type Key=SecretString;

	fn store_name() -> &'static str { K::PREFIX }
	fn get_key(&self) -> &Self::Key { &self.code }
	fn set_key(&mut self, key: &Self::Key) { self.code = key.clone(); }
}

#[derive(PartialEq, Serialize, Deserialize)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct UserSecret<K: UserSecretKind, M>(InternalUserSecret<K, M>);

impl<K: UserSecretKind, M: Serialize + DeserializeOwned + PartialEq> UserSecret<K, M> {
	pub async fn new(user: User, metadata: M, db: &Db) -> Result<Self> {
		let expires_at = chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(K::duration().await)
			.expect(format!("Couldn't generate expiry for {}", K::PREFIX).as_str());

		let internal_secret = InternalUserSecret {
			code: SecretString::new(),
			_kind: PhantomData,
			user,
			expires_at,
			metadata,
		};

		internal_secret.save(db)?;

		Ok(Self(internal_secret))
	}

	pub async fn validate(&self, db: &Db) -> Result<()> {
		if !InternalUserSecret::<K, M>::exists(&self.0.code, db)? {
			return Err(AppErrorKind::TokenNotFound.into());
		}

		if self.0.expires_at <= Utc::now().naive_utc() {
			InternalUserSecret::<K, M>::remove(&self.0.code, db)?;
			return Err(AppErrorKind::ExpiredToken.into());
		}

		Ok(())
	}

	pub async fn try_from_string(db: &Db, code: String) -> Result<Self> {
		let internal_secret = InternalUserSecret::get(&code.into(), db)?.ok_or(AppErrorKind::TokenNotFound)?;
		let user_secret = UserSecret(internal_secret);
		user_secret.validate(db).await?;
		Ok(user_secret)
	}

	pub fn get_code(&self) -> &SecretString { &self.0.code }
	pub fn get_user(&self) -> &User { &self.0.user }
	pub fn get_expires_at(&self) -> NaiveDateTime { self.0.expires_at }
	pub fn get_metadata(&self) -> &M { &self.0.metadata }
}

pub trait UserSecretKindEphemeral: UserSecretKind {
	type ExchangeTo: UserSecretKind;
}

impl<K: UserSecretKindEphemeral, M: Serialize + DeserializeOwned + PartialEq> UserSecret<K, M> {
	pub async fn exchange_with_metadata<NM: Serialize + DeserializeOwned + PartialEq>(self, db: &Db, metadata: NM) -> Result<UserSecret<K::ExchangeTo, NM>> {
		self.validate(db).await?;

		let new_secret = UserSecret::new(self.get_user().clone(), metadata, db).await?;
		InternalUserSecret::<K, M>::remove(&self.0.code, db)?;

		Ok(new_secret)
	}

	pub async fn exchange(self, db: &Db) -> Result<UserSecret<K::ExchangeTo, EmptyMetadata>> {
		self.exchange_with_metadata(db, EmptyMetadata::Instance).await
	}
}
