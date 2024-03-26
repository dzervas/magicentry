use coset::{CoseKey, CborSerializable};
use passkey_authenticator::CredentialStore;
use passkey_types::ctap2::make_credential::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
use passkey_types::ctap2::StatusCode;
use passkey_types::webauthn::PublicKeyCredentialDescriptor;
use passkey_types::Passkey;
use reindeer::Entity;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::future::Future;
use std::pin::Pin;
use std::result::Result;

#[derive(Entity, Debug, Clone, Serialize, Deserialize)]
#[entity(name = "passkey", version = 1)]
pub struct PasskeyStore {
	#[serde(serialize_with = "cosekey_ser", deserialize_with = "cosekey_de")]
	pub key: CoseKey,
	pub id: Vec<u8>,
	pub rp_id: String,
	pub user_handle: Option<Vec<u8>>,
	pub counter: u32,
	pub user: String,
}

impl TryInto<Passkey> for PasskeyStore {
	type Error = crate::error::Error;

	fn try_into(self) -> Result<Passkey, Self::Error> {
		Ok(Passkey {
			key: self.key,
			credential_id: passkey_types::Bytes::from(self.id),
			rp_id: self.rp_id,
			user_handle: self.user_handle.map(|v| passkey_types::Bytes::from(v)),
			counter: Some(self.counter),
		})
	}
}

impl CredentialStore for PasskeyStore {
	type PasskeyItem = Self;

	fn find_credentials<'life0, 'life1, 'life2, 'async_trait>(
		&'life0 self,
		ids: Option<&'life1 [PublicKeyCredentialDescriptor]>,
		rp_id: &'life2 str
	) -> Pin<Box<dyn Future<Output = Result<Vec<Self::PasskeyItem>, StatusCode>> + Send + 'async_trait>>
	where Self: 'async_trait,
			'life0: 'async_trait,
			'life1: 'async_trait,
			'life2: 'async_trait
	{
		todo!()
	}

	fn save_credential<'life0, 'async_trait>(
		&'life0 mut self,
		cred: Passkey,
		user: PublicKeyCredentialUserEntity,
		rp: PublicKeyCredentialRpEntity
	) -> Pin<Box<dyn Future<Output = Result<(), StatusCode>> + Send + 'async_trait>>
	where Self: 'async_trait,
			'life0: 'async_trait
	{
			todo!()
	}


}

fn cosekey_ser<S: Serializer>(key: &CoseKey, serializer: S) -> Result<S::Ok, S::Error> {
	use serde::ser::Error;

	serializer.serialize_bytes(
		key
			.to_vec()
			.map_err(|_|
				Error::custom("Couldn't serialize CoseKey to vec"))?
			.as_slice())
}

fn cosekey_de<'de, D: Deserializer<'de>>(deserializer: D) -> Result<CoseKey, D::Error> {
	use serde::de::Error;

	Ok(CoseKey::from_slice(Deserialize::deserialize(deserializer)?)
			.map_err(|_| Error::custom("Couldn't deserialize CoseKey from slice"))?)
}
