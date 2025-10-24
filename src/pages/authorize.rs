//! Authorization page template (for OIDC/SAML consent)

use maud::{Markup, html};
use crate::pages::partials::{render_page, PageLayout};

/// Authorization page data
#[derive(Debug, Clone)]
pub struct AuthorizePage {
	pub client: String,
	pub name: String,
	pub username: String,
	pub email: String,
	pub path_prefix: String,
	pub title: String,
	// SAML-specific fields
	pub saml_response_data: Option<String>,
	pub saml_relay_state: Option<String>,
	pub saml_acs: Option<String>,
	// OIDC-specific field
	pub link: Option<String>,
}

/// Render authorization page
#[must_use]
pub fn render_authorize_page(page: &AuthorizePage) -> Markup {
	let layout = PageLayout {
		title: page.title.clone(),
		path_prefix: page.path_prefix.clone(),
	};

	let content = html! {
		div {
			h3 { (format!("Log-in to {{{}}} {}", page.client, page.client)) }
			p { "The application will gain access to the following information about you:" }
			ul {
				li { "Full Name: " (&page.name) }
				li { "Username: " (&page.username) }
				li { "E-Mail: " (&page.email) }
			}
			@if let Some(ref saml_data) = page.saml_response_data {
				form method="post" action=(page.saml_acs.as_ref().unwrap_or(&String::new())) id="SAMLResponseForm" {
					input type="hidden" name="SAMLResponse" value=(saml_data) {}
					@if let Some(ref relay_state) = page.saml_relay_state {
						input type="hidden" name="RelayState" value=(relay_state) {}
					}
					input type="submit" value="Continue" {}
				}
			} @else if let Some(ref link) = page.link {
				a href=(link) { "Continue" }
			}
		}
	};

	render_page(&layout, &content)
}
