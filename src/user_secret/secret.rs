use chrono::{NaiveDateTime, Utc};
use reindeer::{Db, Entity};
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::user::User;

use super::{get_prefix, ChildSecretMetadata, SecretString};
use super::metadata::{EmptyMetadata, MetadataKind};

/// This trait describes any kind of user secret.
/// You can think of it as a "token" but I didn't use that term to avoid
/// confusion with all the other types of tokens.
pub trait UserSecretKind: {
	const PREFIX: &'static str;
	type Metadata: MetadataKind;

	async fn duration() -> chrono::Duration;
}

#[derive(PartialEq, Serialize, Deserialize)]
struct InternalUserSecret<K: UserSecretKind> {
	/// The primary key and value of the token. A random string filled by `crate::utils::random_string()`.
	code: SecretString,
	/// The user it authenticates
	#[serde(with = "crate::user::as_string")]
	user: User,
	/// The time the token expires at
	expires_at: NaiveDateTime,
	/// Metadata related to the secret - could be anything to nothing
	metadata: K::Metadata,
}

impl<K: UserSecretKind> Entity for InternalUserSecret<K> {
	type Key=SecretString;

	fn store_name() -> &'static str { K::PREFIX }
	fn get_key(&self) -> &Self::Key { &self.code }
	fn set_key(&mut self, key: &Self::Key) { self.code = key.clone(); }
	fn use_pre_remove_hook() -> bool { true }
}

#[derive(PartialEq, Serialize, Deserialize)]
pub struct UserSecret<K: UserSecretKind>(InternalUserSecret<K>);

impl<K: UserSecretKind> UserSecret<K> {
	pub async fn new(user: User, metadata: K::Metadata, db: &Db) -> Result<Self> {
		let expires_at = chrono::Utc::now()
			.naive_utc()
			.checked_add_signed(K::duration().await)
			.expect(format!("Couldn't generate expiry for {}", K::PREFIX).as_str());

		let internal_secret = InternalUserSecret {
			code: SecretString::new(K::PREFIX),
			user,
			expires_at,
			metadata,
		};

		internal_secret.save(db)?;

		Ok(Self(internal_secret))
	}

	pub async fn validate(&self, db: &Db) -> Result<()> {
		if !self.0.code.0.starts_with(get_prefix(K::PREFIX).as_str()) {
			return Err(AppErrorKind::InvalidToken.into());
		}

		if !InternalUserSecret::<K>::exists(&self.0.code, db)? {
			return Err(AppErrorKind::TokenNotFound.into());
		}

		if self.0.metadata.validate(db).await.is_err() {
			InternalUserSecret::<K>::remove(&self.0.code, db)?;
			return Err(AppErrorKind::InvalidTokenMetadata.into());
		}

		if self.0.expires_at <= Utc::now().naive_utc() {
			InternalUserSecret::<K>::remove(&self.0.code, db)?;
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

	pub fn code(&self) -> &SecretString { &self.0.code }
	pub fn user(&self) -> &User { &self.0.user }
	pub fn expires_at(&self) -> NaiveDateTime { self.0.expires_at }
	pub fn metadata(&self) -> &K::Metadata { &self.0.metadata }
}

impl<P, K, M> UserSecret<K> where
	P : UserSecretKind,
	M : MetadataKind,
	K : UserSecretKind<Metadata=ChildSecretMetadata<P, M>>,
{
	pub fn child_metadata<'a>(&'a self) -> &'a M where P: 'a { self.0.metadata.metadata() }
}

pub trait UserSecretKindEphemeral: UserSecretKind {
	type ExchangeTo: UserSecretKind;
}

impl<K: UserSecretKindEphemeral> UserSecret<K> {
	pub async fn exchange_with_metadata(self, db: &Db, metadata: <K::ExchangeTo as UserSecretKind>::Metadata) -> Result<UserSecret<K::ExchangeTo>> {
		self.validate(db).await?;

		let new_secret = UserSecret::new(self.user().clone(), metadata, db).await?;
		InternalUserSecret::<K>::remove(&self.0.code, db)?;

		Ok(new_secret)
	}
}

impl<K> UserSecret<K> where
	K : UserSecretKindEphemeral<ExchangeTo: UserSecretKind<Metadata=EmptyMetadata>>,
{
	pub async fn exchange(self, db: &Db) -> Result<UserSecret<K::ExchangeTo>> {
		self.exchange_with_metadata(db, EmptyMetadata()).await
	}
}
