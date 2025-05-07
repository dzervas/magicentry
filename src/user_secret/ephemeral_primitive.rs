use std::marker::PhantomData;

use chrono::NaiveDateTime;
use reindeer::{Db, Entity as _};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::user::User;
use crate::error::Result;

use super::primitive::{InternalUserSecret, UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata, MetadataKind, SecretString};

#[derive(Serialize, Deserialize)]
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

	pub async fn try_from_string(code: String, db: &Db) -> Result<Self> {
		Ok(Self(UserSecret::try_from_string(code, db).await?, PhantomData))
	}
	pub fn code(&self) -> &SecretString { &self.0.code() }
	pub fn user(&self) -> &User { &self.0.user() }
	pub fn expires_at(&self) -> NaiveDateTime { self.0.expires_at() }
	pub fn metadata(&self) -> &K::Metadata { &self.0.metadata() }
}

impl<K, ExchangeTo> EphemeralUserSecret<K, ExchangeTo> where
	K : UserSecretKind,
	ExchangeTo : UserSecretKind<Metadata=EmptyMetadata>,
{
	pub async fn exchange(self, db: &Db) -> Result<UserSecret<ExchangeTo>> {
		self.exchange_with_metadata(db, EmptyMetadata()).await
	}
}

impl<P, K, M, ExchangeTo> EphemeralUserSecret<K, ExchangeTo> where
	P : UserSecretKind,
	M : MetadataKind,
	K : UserSecretKind<Metadata=ChildSecretMetadata<P, M>>,
	ExchangeTo : UserSecretKind
{
	pub async fn new_child(parent: UserSecret<P>, metadata: M, db: &Db) -> Result<Self> {
		Ok(Self(UserSecret::<K>::new_child(parent, metadata, db).await?, PhantomData))
	}

	pub fn child_metadata<'a>(&'a self) -> &'a M where P: 'a { self.0.metadata().metadata() }
}

impl<K, M, P, ExchangeTo> EphemeralUserSecret<K, ExchangeTo> where
	P : UserSecretKind + DeserializeOwned + Serialize,
	M : MetadataKind,
	K : UserSecretKind<Metadata=ChildSecretMetadata<P, M>>,
	ExchangeTo : UserSecretKind<Metadata=ChildSecretMetadata<P, EmptyMetadata>>,
{
	pub async fn exchange_sibling(self, db: &Db) -> Result<UserSecret<ExchangeTo>> {
		self.0.validate(db).await?;
		InternalUserSecret::<K>::remove(&self.0.code(), db)?;
		let user = self.0.user().clone();
		let metadata = self.0.take_metadata().to_empty();

		let new_secret = UserSecret::new(user, metadata, db).await?;

		Ok(new_secret)
	}
}
