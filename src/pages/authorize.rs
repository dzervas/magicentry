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
			div class="relative p-4 w-full max-w-md h-full md:h-auto" {
				div class="relative p-4 text-center bg-white rounded-lg shadow-sm dark:bg-gray-800 sm:p-5" {
					h3 class="mb-4 text-lg font-semibold text-gray-900 dark:text-white" {
						"Log-in to"
						span class="text-3xl sm:text-3xl text-gray-400 dark:text-gray-500"
							style="position: relative; bottom: -2px" { "{" }
						(self.client)
						span class="text-3xl sm:text-3xl text-gray-400 dark:text-gray-500"
							style="position: relative; bottom: -2px" { "}" }
					}
					p class="mb-4 font-light text-gray-500 dark:text-gray-400" { "The application will gain access to the following information about you:" }
					ul role="list" class="mb-4 space-y-4 text-left mb-5" {
						li class="flex items-center space-x-2 text-gray-900 dark:text-white" {
							svg aria-hidden="true" class="shrink-0 w-4 h-4 text-green-400 dark:text-green-500" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" {
								path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" {}
							}
							span class="text-gray-500 dark:text-gray-400" { "Full Name:" }
							p { (&self.name) }
						}
						li class="flex items-center space-x-2 text-gray-900 dark:text-white" {
							svg aria-hidden="true" class="shrink-0 w-4 h-4 text-green-400 dark:text-green-500" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" {
								path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" {}
							}
							span class="text-gray-500 dark:text-gray-400" { "Username:" }
							p { (&self.username) }
						}
						li class="flex items-center space-x-2 text-gray-900 dark:text-white" {
							svg aria-hidden="true" class="shrink-0 w-4 h-4 text-green-400 dark:text-green-500" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" {
								path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" {}
							}
							span class="text-gray-500 dark:text-gray-400" { "E-Mail:" }
							p { (&self.email) }
						}
					}
					@if let Some(ref saml_data) = self.saml_response_data {
						form method="post" action=(self.saml_acs.as_ref().unwrap_or(&String::new())) id="SAMLResponseForm" {
							input type="hidden" name="SAMLResponse" value=(saml_data) {}
							@if let Some(ref relay_state) = self.saml_relay_state {
								input type="hidden" name="RelayState" value=(relay_state) {}
							}
							input type="submit" value="Continue" data-modal-toggle="successListModal" class="py-2 px-3 text-sm font-medium text-center text-white rounded-lg bg-primary-600 hover:bg-primary-700 focus:ring-4 focus:outline-hidden focus:ring-primary-300 dark:focus:ring-primary-900" {}
						}
					} @else if let Some(ref link) = self.link {
						a href=(link) type="button" data-modal-toggle="successListModal" class="py-2 px-3 text-sm font-medium text-center text-white rounded-lg bg-primary-600 hover:bg-primary-700 focus:ring-4 focus:outline-hidden focus:ring-primary-300 dark:focus:ring-primary-900" {
							"Continue"
						}
					}
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
