//! Authorization page template (for OIDC/SAML consent)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::config::Config;

use super::Page;

/// Authorization page data
#[derive(Debug, Clone)]
pub struct AuthorizePage {
	pub client: String,
	pub name: String,
	pub username: String,
	pub email: String,
	// SAML-specific fields
	pub saml_response_data: Option<String>,
	pub saml_relay_state: Option<String>,
	pub saml_acs: Option<String>,
	// OIDC-specific field
	pub link: Option<String>,
}

#[async_trait]
impl Page for AuthorizePage {
	fn render_partial(&self) -> Markup {
		html! {
			div {
				h3 { (format!("Log-in to {{{}}} {}", self.client, self.client)) }
				p { "The application will gain access to the following information about you:" }
				ul {
					li { "Full Name: " (&self.name) }
					li { "Username: " (&self.username) }
					li { "E-Mail: " (&self.email) }
				}
				@if let Some(ref saml_data) = self.saml_response_data {
					form method="post" action=(self.saml_acs.as_ref().unwrap_or(&String::new())) id="SAMLResponseForm" {
						input type="hidden" name="SAMLResponse" value=(saml_data) {}
						@if let Some(ref relay_state) = self.saml_relay_state {
							input type="hidden" name="RelayState" value=(relay_state) {}
						}
						input type="submit" value="Continue" {}
					}
				} @else if let Some(ref link) = self.link {
					a href=(link) { "Continue" }
				}
			}
		}
	}

	fn get_title<'a>(&'a self, config: &'a Config) -> &'a str {
		&config.title
	}

	fn get_path_prefix<'a>(&'a self, config: &'a Config) -> &'a str {
		&config.path_prefix
	}
}
