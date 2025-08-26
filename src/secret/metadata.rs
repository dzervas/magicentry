use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::primitive::{UserSecret, UserSecretKind};

use crate::database::Database;
use crate::error::Result;

/// The trait that needs to be implemented by all metadata types.
/// Just a trait alias.

pub trait MetadataKind: Serialize + DeserializeOwned {
	async fn validate(&self, _db: &Database) -> Result<()> { Ok(()) }
}

impl MetadataKind for webauthn_rs::prelude::PasskeyAuthentication {}
impl MetadataKind for webauthn_rs::prelude::PasskeyRegistration {}
impl MetadataKind for String {}
impl MetadataKind for url::Url {}
impl<T: MetadataKind> MetadataKind for Option<T> {}

/// Zero-sized struct for empty metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmptyMetadata();

impl MetadataKind for EmptyMetadata {}

impl From<()> for EmptyMetadata {
	fn from(_: ()) -> Self { EmptyMetadata() }
}

/// This struct is used to denote that a secret is a child of another secret.
/// It contains the parent secret primary key and the actual metadata.
///
/// When the parent secret is deleted, this secret will be deleted as well.
#[derive(Serialize, Deserialize)]
pub struct ChildSecretMetadata<P: UserSecretKind, M> {
	parent: UserSecret<P>,
	metadata: M,
}

impl<P: UserSecretKind, M: MetadataKind> ChildSecretMetadata<P, M> {
	pub(super) fn new(parent: UserSecret<P>, metadata: M) -> Self {
		Self { parent, metadata }
	}

	pub fn parent(&self) -> &UserSecret<P> { &self.parent }
	pub fn metadata(&self) -> &M { &self.metadata }

	pub(super) fn to_empty(self) -> ChildSecretMetadata<P, EmptyMetadata> { ChildSecretMetadata { parent: self.parent, metadata: EmptyMetadata() } }
}

impl<P: UserSecretKind + PartialEq + Serialize + DeserializeOwned, M: MetadataKind> MetadataKind for ChildSecretMetadata<P, M> {
	async fn validate(&self, db: &Database) -> Result<()> {
		self.metadata.validate(db).await?;
		self.parent.validate(db).await?;
		Ok(())
	}
}

// impl<P, M, S, SM> ChildSecretMetadata<P, M> where
// 	M : MetadataKind,
// 	SM : MetadataKind,
// 	S : UserSecretKind,
// 	P : UserSecretKind<Metadata=ChildSecretMetadata<S, SM>>,
// {
// 	pub fn to_sibling_with_metadata(self, metadata: SM) -> ChildSecretMetadata<S, SM> {
// 		ChildSecretMetadata::new(self.parent, metadata)
// 	}
// }
