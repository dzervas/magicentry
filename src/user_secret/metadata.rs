use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::SecretString;

/// The trait that needs to be implemented by all metadata types.
/// Just a trait alias.
#[cfg(debug_assertions)]
pub trait MetadataKind: PartialEq + std::fmt::Debug + Serialize + DeserializeOwned {}
#[cfg(not(debug_assertions))]
pub trait MetadataKind: PartialEq + Serialize + DeserializeOwned {}

impl<T: PartialEq + std::fmt::Debug + Serialize + DeserializeOwned> MetadataKind for T {}

/// Zero-sized struct for empty metadata.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EmptyMetadata();

/// This struct is used to denote that a secret is a child of another secret.
/// It contains the parent secret primary key and the actual metadata.
///
/// When the parent secret is deleted, this secret will be deleted as well.
#[derive(PartialEq, Serialize, Deserialize)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub struct ChildSecretMetadata<M> {
	pub parent: SecretString,
	pub metadata: M,
}

#[cfg(not(debug_assertions))]
impl<M: MetadataKind> MetadataKind for ChildSecretMetadata<M> {}
