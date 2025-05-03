use std::marker::PhantomData;

use chrono::NaiveDateTime;
use reindeer::{Db, Entity as _};

use crate::user::User;
use crate::error::Result;

use super::secret::{InternalUserSecret, UserSecret, UserSecretKind};
use super::{EmptyMetadata, SecretString};

pub struct EphemeralUserSecret<K: UserSecretKind, ExchangeTo: UserSecretKind>(UserSecret<K>, PhantomData<ExchangeTo>);

impl<K: UserSecretKind, ExchangeTo: UserSecretKind> EphemeralUserSecret<K, ExchangeTo> {
	pub async fn new(user: User, metadata: K::Metadata, db: &Db) -> Result<Self> {
		Ok(Self(UserSecret::new(user, metadata, db).await?, PhantomData))
	}

	pub async fn exchange_with_metadata(self, db: &Db, metadata: <ExchangeTo as UserSecretKind>::Metadata) -> Result<UserSecret<ExchangeTo>> {
		self.0.validate(db).await?;

		let new_secret = UserSecret::new(self.0.user().clone(), metadata, db).await?;
		InternalUserSecret::<K>::remove(&self.0.code(), db)?;

		Ok(new_secret)
	}

	pub async fn try_from_string(db: &Db, code: String) -> Result<Self> {
		Ok(Self(UserSecret::try_from_string(db, code).await?, PhantomData))
	}
	pub fn code(&self) -> &SecretString { &self.0.code() }
	pub fn user(&self) -> &User { &self.0.user() }
	pub fn expires_at(&self) -> NaiveDateTime { self.0.expires_at() }
	pub fn metadata(&self) -> &K::Metadata { &self.0.metadata() }
}

impl<K, ExchangeTo: UserSecretKind> EphemeralUserSecret<K, ExchangeTo> where
	K : UserSecretKind,
	ExchangeTo : UserSecretKind<Metadata=EmptyMetadata>,
{
	pub async fn exchange(self, db: &Db) -> Result<UserSecret<ExchangeTo>> {
		self.exchange_with_metadata(db, EmptyMetadata()).await
	}
}
