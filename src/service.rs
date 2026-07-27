use serde::{Deserialize, Serialize};

use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
	pub name: String,
	pub url: url::Url,
	pub realms: Vec<String>,
	pub auth_url: Option<ServiceAuthUrl>,
	pub oidc: Option<ServiceOIDC>,
	pub saml: Option<ServiceSAML>,
}

impl Service {
	#[must_use]
	pub fn is_user_allowed(&self, user: &User) -> bool {
		user.has_any_realm(&self.realms)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceAuthUrl {
	// TODO: Use url::Origin with custom de/serialization
	pub origins: Vec<String>,
	/// Optional endpoint to ask the protected application whether the incoming
	/// user is authenticated.
	pub status_url: Option<url::Url>,
	/// Cookie names forwarded to `status_url` when performing the auth check.
	pub status_cookies: Option<Vec<String>>,
	/// Request headers (by name) to forward to `status_url` when performing the auth check.
	pub status_headers: Option<Vec<String>>,
	/// Optional authentication info for `status_url`.
	pub status_auth: Option<StatusAuth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StatusAuth {
	Basic { username: String, password: String },
	Bearer { token: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSAML {
	pub entity_id: String,
	pub redirect_urls: Vec<url::Url>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum IdTokenSigningAlgorithm {
	#[default]
	#[serde(rename = "RS256")]
	RS256,
	#[serde(rename = "HS256")]
	HS256,
}

impl From<IdTokenSigningAlgorithm> for jsonwebtoken::Algorithm {
	fn from(value: IdTokenSigningAlgorithm) -> Self {
		match value {
			IdTokenSigningAlgorithm::RS256 => Self::RS256,
			IdTokenSigningAlgorithm::HS256 => Self::HS256,
		}
	}
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceOIDC {
	pub client_id: String,
	pub client_secret: String,
	#[serde(default)]
	pub signing_alg: IdTokenSigningAlgorithm,
	pub redirect_urls: Vec<url::Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Services(pub Vec<Service>);

impl Services {
	pub fn get(&self, name: &str) -> Option<&Service> {
		self.0.iter().find(|s| s.name == name)
	}

	pub fn get_mut(&mut self, name: &str) -> Option<&mut Service> {
		self.0.iter_mut().find(|s| s.name == name)
	}

	/// Returns all the services that the provided user has access to
	pub fn from_user(&self, user: &User) -> Self {
		let res = self
			.0
			.iter()
			.filter(|s| user.has_any_realm(&s.realms))
			.cloned()
			.collect();

		Self(res)
	}

	/// Returns the first service that matches the given OIDC client ID
	pub fn from_oidc_client_id(&self, client_id: &str) -> Option<Service> {
		self.0
			.iter()
			.find(|s| s.oidc.as_ref().is_some_and(|o| o.client_id == client_id))
			.cloned()
	}

	/// Returns the first service that matches the given OIDC redirect URL
	pub fn from_oidc_redirect_url(&self, redirect_url: &url::Url) -> Option<Service> {
		self.0
			.iter()
			.find(|s| {
				s.oidc
					.as_ref()
					.is_some_and(|o| o.redirect_urls.contains(redirect_url))
			})
			.cloned()
	}

	/// Returns the first service that matches the given SAML entity ID
	pub fn from_saml_entity_id(&self, entity_id: &str) -> Option<Service> {
		self.0
			.iter()
			.find(|s| s.saml.as_ref().is_some_and(|o| o.entity_id == entity_id))
			.cloned()
	}

	/// Returns the first service that matches the given redirect URL
	pub fn from_saml_redirect_url(&self, redirect_url: &url::Url) -> Option<Service> {
		self.0
			.iter()
			.find(|s| {
				s.saml
					.as_ref()
					.is_some_and(|o| o.redirect_urls.contains(redirect_url))
			})
			.cloned()
	}

	/// Returns the first service that matches the given redirect URL
	pub fn from_auth_url_origin(&self, origin: &url::Origin) -> Option<Service> {
		let origin_str = origin.ascii_serialization();
		self.0
			.iter()
			.find(|s| {
				s.auth_url
					.as_ref()
					.is_some_and(|o| o.origins.contains(&origin_str))
			})
			.cloned()
	}
}

#[cfg(test)]
mod tests {
	use super::{IdTokenSigningAlgorithm, ServiceOIDC};

	#[test]
	fn oidc_signing_algorithm_is_configurable_and_defaults_to_rs256() {
		let oidc: ServiceOIDC = serde_json::from_value(serde_json::json!({
			"client_id": "client-id",
			"client_secret": "client-secret",
			"redirect_urls": []
		}))
		.unwrap();

		assert_eq!(oidc.signing_alg, IdTokenSigningAlgorithm::RS256);

		let oidc: ServiceOIDC = serde_json::from_value(serde_json::json!({
			"client_id": "client-id",
			"client_secret": "client-secret",
			"signing_alg": "HS256",
			"redirect_urls": []
		}))
		.unwrap();
		assert_eq!(oidc.signing_alg, IdTokenSigningAlgorithm::HS256);
	}
}
