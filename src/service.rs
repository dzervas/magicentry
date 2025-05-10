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
	pub fn is_user_allowed(&self, user: &User) -> bool {
		user.has_any_realm(&self.realms)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAuthUrl {
	// TODO: Use url::Origin with custom de/serialization
	pub origins: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSAML {
	pub entity_id: String,
	pub redirect_urls: Vec<url::Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceOIDC {
	pub client_id: String,
	pub client_secret: String,
	pub redirect_urls: Vec<url::Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Services(pub Vec<Service>);

impl Services {
	/// Returns all the services that the provided user has access to
	pub fn from_user(&self, user: &User) -> Self {
		let res = self.0.iter()
			.filter(|s| user.has_any_realm(&s.realms))
			.cloned()
			.collect();

		Self(res)
	}

	/// Returns the first service that matches the given OIDC client ID
	pub fn from_oidc_client_id(&self, client_id: &str) -> Option<Service> {
		self.0.iter()
			.find(|s| s.oidc.as_ref()
				.map_or(false, |o| o.client_id == client_id))
			.cloned()
	}

	/// Returns the first service that matches the given OIDC redirect URL
	pub fn from_oidc_redirect_url(&self, redirect_url: &url::Url) -> Option<Service> {
		self.0.iter()
			.find(|s| s.oidc.as_ref()
				.map_or(false, |o| o.redirect_urls.contains(&redirect_url)))
			.cloned()
	}

	/// Returns the first service that matches the given SAML entity ID
	pub fn from_saml_entity_id(&self, entity_id: &str) -> Option<Service> {
		self.0.iter()
			.find(|s| s.saml.as_ref()
				.map_or(false, |o| o.entity_id == entity_id))
			.cloned()
	}

	/// Returns the first service that matches the given redirect URL
	pub fn from_saml_redirect_url(&self, redirect_url: &url::Url) -> Option<Service> {
		self.0.iter()
			.find(|s| s.saml.as_ref()
				.map_or(false, |o| o.redirect_urls.contains(&redirect_url)))
			.cloned()
	}


	/// Returns the first service that matches the given redirect URL
	pub fn from_auth_url_origin(&self, origin: &url::Origin) -> Option<Service> {
		let origin_str = origin.ascii_serialization();
		self.0.iter()
			.find(|s| s.auth_url.as_ref()
				.map_or(false, |o| o.origins.contains(&origin_str)))
			.cloned()
	}
}
