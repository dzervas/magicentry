use serde::{Deserialize, Serialize};

use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
	pub name: String,
	pub url: String,
	pub realms: Vec<String>,
	pub valid_origins: Vec<String>,
	pub oidc: Option<ServiceOIDC>,
	pub saml: Option<ServiceSAML>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceOIDC {
	pub client_id: String,
	pub client_secret: String,
	pub redirect_urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSAML {
	pub entity_id: String,
	pub redirect_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Services(pub Vec<Service>);

impl Services {
	pub fn from_user(&self, user: &User) -> Self {
		let res = self.0.iter()
			.filter(|s| user.has_any_realm(&s.realms))
			.cloned()
			.collect();

		Self(res)
	}

	/// Returns the service with the OIDC client ID
	pub fn from_oidc_client_id(&self, client_id: &str) -> Option<Service> {
		self.0.iter()
			.find(|s| s.oidc.as_ref().map_or(false, |o| o.client_id == client_id))
			.cloned()
	}

	/// Returns the service with the valid redirect URL
	pub fn from_oidc_redirect_url(&self, redirect_url: &str) -> Option<Service> {
		self.0.iter()
			.find(|s| s.oidc.as_ref().map_or(false, |o| o.redirect_urls.contains(&redirect_url.to_string())))
			.cloned()
	}

	/// Returns the service with the valid redirect URL and checks if the user has any of the realms
	pub fn from_oidc_redirect_url_with_realms(&self, redirect_url: &str, user: &User) -> Option<Service> {
		self.from_user(user).from_oidc_redirect_url(redirect_url)
	}

	/// Returns the service with the OIDC client ID and checks if the user has any of the realms
	pub fn from_oidc_client_id_with_realms(&self, client_id: &str, user: &User) -> Option<Service> {
		self.from_user(user).from_oidc_client_id(client_id)
	}

	/// Returns the service with the SAML entity ID
	pub fn from_origin(&self, origin: &str) -> Option<Service> {
		self.0.iter()
			.find(|s| s.valid_origins.contains(&origin.to_string()))
			.cloned()
	}

	pub fn from_origin_with_realms(&self, origin: &str, user: &User) -> Option<Service> {
		self.from_user(user).from_origin(origin)
	}
}
