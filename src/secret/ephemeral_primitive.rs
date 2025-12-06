use std::marker::PhantomData;

use chrono::NaiveDateTime;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::AppError;
use crate::user::User;

use super::primitive::{InternalUserSecret, UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata, MetadataKind, SecretString};

#[derive(Serialize, Deserialize)]
pub struct EphemeralUserSecret<K: UserSecretKind, ExchangeTo: UserSecretKind>(
	UserSecret<K>,
	PhantomData<ExchangeTo>,
);

impl<K: UserSecretKind, ExchangeTo: UserSecretKind> EphemeralUserSecret<K, ExchangeTo> {
	pub async fn new(
		user: User,
		metadata: K::Metadata,
		config: &LiveConfig,
		db: &crate::Database,
	) -> Result<Self, AppError> {
		Ok(Self(
			UserSecret::new(user, metadata, config, db).await?,
			PhantomData,
		))
	}

	pub async fn exchange_with_metadata(
		self,
		config: &LiveConfig,
		db: &crate::Database,
		metadata: <ExchangeTo as UserSecretKind>::Metadata,
	) -> Result<UserSecret<ExchangeTo>, AppError> {
		self.0.validate(db).await?;

		let new_secret = UserSecret::new(self.0.user().clone(), metadata, config, db).await?;
		InternalUserSecret::<K>::remove(self.0.code(), db).await?;

		Ok(new_secret)
	}

	pub async fn try_from_string(code: String, db: &crate::Database) -> Result<Self, AppError> {
		Ok(Self(
			UserSecret::try_from_string(code, db).await?,
			PhantomData,
		))
	}
	pub const fn code(&self) -> &SecretString {
		self.0.code()
	}
	pub const fn user(&self) -> &User {
		self.0.user()
	}
	pub const fn expires_at(&self) -> NaiveDateTime {
		self.0.expires_at()
	}
	pub const fn metadata(&self) -> &K::Metadata {
		self.0.metadata()
	}
}

impl<K, ExchangeTo> EphemeralUserSecret<K, ExchangeTo>
where
	K: UserSecretKind,
	ExchangeTo: UserSecretKind<Metadata = EmptyMetadata>,
{
	pub async fn exchange(
		self,
		config: &LiveConfig,
		db: &crate::Database,
	) -> Result<UserSecret<ExchangeTo>, AppError> {
		self.exchange_with_metadata(config, db, EmptyMetadata())
			.await
	}
}

impl<P, K, M, ExchangeTo> EphemeralUserSecret<K, ExchangeTo>
where
	P: UserSecretKind,
	M: MetadataKind,
	K: UserSecretKind<Metadata = ChildSecretMetadata<P, M>>,
	ExchangeTo: UserSecretKind,
{
	pub async fn new_child(
		parent: UserSecret<P>,
		metadata: M,
		config: &LiveConfig,
		db: &crate::Database,
	) -> Result<Self, AppError> {
		Ok(Self(
			UserSecret::<K>::new_child(parent, metadata, config, db).await?,
			PhantomData,
		))
	}

	pub const fn child_metadata<'a>(&'a self) -> &'a M
	where
		P: 'a,
	{
		self.0.metadata().metadata()
	}
}

impl<K, M, P, ExchangeTo> EphemeralUserSecret<K, ExchangeTo>
where
	P: UserSecretKind + DeserializeOwned + Serialize,
	M: MetadataKind,
	K: UserSecretKind<Metadata = ChildSecretMetadata<P, M>>,
	ExchangeTo: UserSecretKind<Metadata = ChildSecretMetadata<P, EmptyMetadata>>,
{
	pub async fn exchange_sibling(
		self,
		config: &LiveConfig,
		db: &crate::Database,
	) -> Result<UserSecret<ExchangeTo>, AppError> {
		self.0.validate(db).await?;
		InternalUserSecret::<K>::remove(self.0.code(), db).await?;
		let user = self.0.user().clone();
		let metadata = self.0.take_metadata().into_empty();

		let new_secret = UserSecret::new(user, metadata, config, db).await?;

		Ok(new_secret)
	}
}
