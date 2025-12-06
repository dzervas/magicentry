#![allow(async_fn_in_trait)]
pub mod cleanup;
pub mod ephemeral_primitive;
pub mod metadata;
pub mod primitive;

// Secret types
pub mod browser_session;
pub mod login_link;
pub mod oidc_authcode;
pub mod oidc_token;
pub mod proxy_code;
pub mod proxy_session;
pub mod webauthn_auth;
pub mod webauthn_reg;

pub use browser_session::BrowserSessionSecret;
pub use login_link::LoginLinkSecret;
pub use metadata::{ChildSecretMetadata, EmptyMetadata, MetadataKind};
pub use oidc_authcode::OIDCAuthCodeSecret;
pub use oidc_token::OIDCTokenSecret;
pub use proxy_code::ProxyCodeSecret;
pub use proxy_session::ProxySessionSecret;
pub use webauthn_auth::WebAuthnAuthSecret;
pub use webauthn_reg::WebAuthnRegSecret;

use serde::{Deserialize, Serialize};

use crate::{error::AuthError, utils::random_string};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Encode, sqlx::Decode)]
pub enum SecretType {
	ApiKey,
	BrowserSession,
	LoginLink,
	MagicToken,
	OIDCAuthCode,
	OIDCToken,
	ProxyCode,
	ProxySession,
	WebAuthnAuth,
	WebAuthnReg,
}

impl SecretType {
	#[must_use]
	pub const fn as_short_str(&self) -> &'static str {
		match self {
			Self::ApiKey => "aa",
			Self::BrowserSession => "bs",
			Self::LoginLink => "ll",
			Self::MagicToken => "mt",
			Self::OIDCAuthCode => "oa",
			Self::OIDCToken => "ot",
			Self::ProxyCode => "pc",
			Self::ProxySession => "ps",
			Self::WebAuthnAuth => "wa",
			Self::WebAuthnReg => "wr",
		}
	}
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretString(SecretType, String);

impl SecretString {
	#[must_use]
	pub fn new(kind: &SecretType) -> Self {
		Self(kind.clone(), random_string())
	}

	#[must_use]
	pub const fn get_type(&self) -> &SecretType {
		&self.0
	}

	#[allow(clippy::must_use_candidate)]
	pub fn to_str_that_i_wont_print(&self) -> String {
		self.with_prefix()
	}

	#[must_use]
	fn with_prefix(&self) -> String {
		format!("me_{}_{}", self.0.as_short_str(), self.1)
	}
}

/// Store the secret as a normal string in the db with the prefix (e.g. `me_bs_XXXX`)
impl sqlx::Encode<'_, sqlx::Sqlite> for SecretString {
	fn encode_by_ref(
		&self,
		buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'_>,
	) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
		sqlx::Encode::<sqlx::Sqlite>::encode_by_ref(&self.with_prefix(), buf)
	}
}

/// Retrieve the secret from the db as a normal string and parse it,
/// populating its type in the process
impl sqlx::Decode<'_, sqlx::Sqlite> for SecretString {
	fn decode(
		value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'_>,
	) -> Result<Self, sqlx::error::BoxDynError> {
		let s = <String as sqlx::Decode<'_, sqlx::Sqlite>>::decode(value)?;
		Ok(s.try_into()?)
	}
}

/// Forward the type info from String to `SQLx` (if String works, [`SecretString`] works)
impl sqlx::Type<sqlx::Sqlite> for SecretString {
	fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
		<String as sqlx::Type<sqlx::Sqlite>>::type_info()
	}
}

#[cfg(debug_assertions)]
impl std::fmt::Debug for SecretString {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.1.fmt(f)
	}
}

#[cfg(debug_assertions)]
impl std::fmt::Display for SecretString {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.1.fmt(f)
	}
}

impl TryFrom<String> for SecretString {
	type Error = crate::error::AppError;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		let parts: Vec<_> = value.split('_').collect();
		if parts.len() != 3 || parts[0] != "me" {
			return Err(AuthError::InvalidSecret.into());
		}

		let kind = match parts[1] {
			"aa" => SecretType::ApiKey,
			"bs" => SecretType::BrowserSession,
			"ll" => SecretType::LoginLink,
			"mt" => SecretType::MagicToken,
			"oa" => SecretType::OIDCAuthCode,
			"ot" => SecretType::OIDCToken,
			"pc" => SecretType::ProxyCode,
			"ps" => SecretType::ProxySession,
			"wa" => SecretType::WebAuthnAuth,
			"wr" => SecretType::WebAuthnReg,
			_ => return Err(AuthError::InvalidSecret.into()),
		};

		Ok(Self(kind, parts[2].to_string()))
	}
}
