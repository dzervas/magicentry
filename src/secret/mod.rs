#![allow(async_fn_in_trait)]
pub mod primitive;
pub mod ephemeral_primitive;
pub mod metadata;
pub mod cleanup;

// Secret types
pub mod browser_session;
pub mod login_link;
pub mod proxy_code;
pub mod proxy_session;
pub mod oidc_token;
pub mod oidc_authcode;
pub mod webauthn_auth;
pub mod webauthn_reg;

pub use browser_session::BrowserSessionSecret;
pub use login_link::LoginLinkSecret;
pub use proxy_code::ProxyCodeSecret;
pub use proxy_session::ProxySessionSecret;
pub use oidc_authcode::OIDCAuthCodeSecret;
pub use oidc_token::OIDCTokenSecret;
pub use webauthn_auth::WebAuthnAuthSecret;
pub use webauthn_reg::WebAuthnRegSecret;
pub use metadata::{MetadataKind, ChildSecretMetadata, EmptyMetadata};

use serde::{Deserialize, Serialize};

use crate::{database::UserSecretType, utils::random_string};

#[must_use]
pub fn get_prefix<S: AsRef<str>>(prefix: S) -> String {
	format!("me_{}_", prefix.as_ref())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretString(String);

impl SecretString {
	#[allow(clippy::must_use_candidate)]
	pub fn to_str_that_i_wont_print(&self) -> &str { &self.0 }
}

impl SecretString {
	#[must_use]
	pub fn new(kind: &UserSecretType) -> Self {
		let prefix = get_prefix(kind.as_short_str());

		Self(format!("{prefix}{}", random_string()))
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

#[cfg(debug_assertions)]
impl std::fmt::Display for SecretString {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}
