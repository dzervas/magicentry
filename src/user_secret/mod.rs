#![allow(async_fn_in_trait)]
pub mod secret;
pub mod ephemeral_secret;
pub mod metadata;

// Secret types
pub mod browser_session;
pub mod link_login;
pub mod proxy_code;
pub mod proxy_session;

pub use browser_session::BrowserSessionSecret;
pub use link_login::LinkLoginSecret;
pub use proxy_code::ProxyCodeSecret;
pub use metadata::{MetadataKind, ChildSecretMetadata, EmptyMetadata};

use reindeer::AsBytes;
use serde::{Deserialize, Serialize};

use crate::utils::random_string;

pub fn get_prefix(prefix: &str) -> String {
	format!("me_{}_", prefix)
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretString(String);

impl SecretString {
	pub fn to_str_that_i_wont_print(&self) -> &str { &self.0 }
}

// Needed for reindeer
impl AsBytes for SecretString {
	fn as_bytes(&self) -> Vec<u8> { self.0.as_bytes().to_owned() }
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
