#![allow(async_fn_in_trait)]
pub mod cleanup;
pub mod ephemeral_primitive;
pub mod metadata;
pub mod primitive;

// Secret types
pub mod api_key;
pub mod browser_session;
pub mod login_link;
pub mod oidc_authcode;
pub mod oidc_token;
pub mod proxy_code;
pub mod proxy_session;
pub mod webauthn_auth;
pub mod webauthn_reg;

pub use api_key::{ApiKeyInfo, ApiKeySecret};
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

use crate::utils::random_string;

pub fn get_prefix(prefix: &str) -> String {
	format!("me_{}_", prefix)
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretString(String);

impl SecretString {
	pub fn to_str_that_i_wont_print(&self) -> &str {
		&self.0
	}
}

impl SecretString {
	pub fn new(prefix: &'static str) -> Self {
		Self(format!("{}{}", get_prefix(prefix), random_string()))
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
