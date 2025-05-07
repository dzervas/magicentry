use chrono::{NaiveDateTime, Utc};
use reindeer::{Db, Entity};
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::user::User;

use super::{get_prefix, ChildSecretMetadata, SecretString};
use super::metadata::MetadataKind;

/// This trait describes any kind of user secret.
/// You can think of it as a "token" but I didn't use that term to avoid
/// confusion with all the other types of tokens.
pub trait UserSecretKind: {
	const PREFIX: &'static str;
	type Metadata: MetadataKind;

	async fn duration() -> chrono::Duration;
}

#[derive(PartialEq, Serialize, Deserialize)]
pub(super) struct InternalUserSecret<K: UserSecretKind> {
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

#[derive(Serialize, Deserialize)]
pub struct UserSecret<K: UserSecretKind>(InternalUserSecret<K>);

/// Basic user secret operations
impl<K: UserSecretKind> UserSecret<K> {
	/// Create a new user secret that is bound to a user and has some metadata
	pub async fn new(user: User, metadata: K::Metadata, db: &Db) -> Result<Self> {
		metadata.validate(db).await?;

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

	/// Validate that the secret exists in the db and is not expired
	/// It also validates the metadata, if any such logic is implemented in them
	///
	/// Any failure will remove the secret from the db and return an error
	/// This is useful for cleaning up expired secrets
	pub async fn validate(&self, db: &Db) -> Result<()> {
		if !self.0.code.0.starts_with(get_prefix(K::PREFIX).as_str()) {
			return Err(AppErrorKind::InvalidSecretType.into());
		}

		if self.0.expires_at <= Utc::now().naive_utc() {
			InternalUserSecret::<K>::remove(&self.0.code, db)?;
			return Err(AppErrorKind::ExpiredSecret.into());
		}

		if !InternalUserSecret::<K>::exists(&self.0.code, db)? {
			return Err(AppErrorKind::SecretNotFound.into());
		}

		if self.0.metadata.validate(db).await.is_err() {
			InternalUserSecret::<K>::remove(&self.0.code, db)?;
			return Err(AppErrorKind::InvalidSecretMetadata.into());
		}

		Ok(())
	}

	/// Just delete the secret from the db
	pub async fn delete(self, db: &Db) -> Result<()> {
		Ok(InternalUserSecret::<K>::remove(&self.0.code, db)?)
	}

	/// Parse and validate a secret from a string - most probably from user controlled data
	pub async fn try_from_string(code: String, db: &Db) -> Result<Self> {
		let internal_secret = InternalUserSecret::get(&code.into(), db)?.ok_or(AppErrorKind::SecretNotFound)?;
		let user_secret = UserSecret(internal_secret);
		user_secret.validate(db).await?;
		Ok(user_secret)
	}

	pub fn code(&self) -> &SecretString { &self.0.code }
	pub fn user(&self) -> &User { &self.0.user }
	pub fn expires_at(&self) -> NaiveDateTime { self.0.expires_at }
	pub fn metadata(&self) -> &K::Metadata { &self.0.metadata }
	pub fn take_metadata(self) -> K::Metadata { self.0.metadata }
}

/// Operations for user secrets that are bound to a parent secret
///
/// For example a [`ProxySessionSecret`](super::proxy_session::ProxySessionSecret) is bound to a [`BrowserSessionSecret`](super::browser_session::BrowserSessionSecret)
/// since we only want the proxy session to be able to access its application data
///
/// As soon as the parent secret is deleted (or expired) the child secret will be invalidated
/// and eventually deleted as well during metadata validation
impl<P, K, M> UserSecret<K> where
	P : UserSecretKind,
	M : MetadataKind,
	K : UserSecretKind<Metadata=ChildSecretMetadata<P, M>>,
{
	pub async fn new_child(parent: UserSecret<P>, metadata: M, db: &Db) -> Result<Self> {
		UserSecret::<K>::new(parent.user().clone(), ChildSecretMetadata::new(parent, metadata), db).await
	}

	pub fn child_metadata<'a>(&'a self) -> &'a M where P: 'a { self.0.metadata.metadata() }
}

// TODO: Create a blanket implementation of FromRequest for UserSecret instances that implement a FromRequestAsync trait so that the async-related boilerplate can go away
