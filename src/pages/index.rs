//! Index page template (shown after successful login)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::partials::{script, PageLayout};
use crate::pages::Page;
use crate::config::Config;

/// Service information for index page
#[derive(Debug, Clone)]
pub struct ServiceInfo {
	pub name: String,
	pub url: String,
}

/// Index page data
#[derive(Debug, Clone)]
pub struct IndexPage {
	pub email: String,
	pub services: Vec<ServiceInfo>,
}

#[async_trait]
impl Page for IndexPage {
	fn render_partial(&self, config: &Config) -> Markup {
		let layout = get_page_layout_from_config(config);
		html! {
			header {
				p { b { (format!("Welcome back {}", self.email)) } }
				button id="webauthn-register" { "Register PassKey" }
				a href="/logout" { "Logout" }
			}
			table {
				tbody {
					@for service in &self.services {
						tr {
							td {
								object data=(format!("{}/favicon.ico", service.url)) type="image/x-icon" {
									img src=(format!("{}/static/app-placeholder.svg", layout.path_prefix)) {}
								}
								div {
									a href=(&service.url) {
										div { (&service.name) }
									}
									div { "realm" }
								}
							}
						}
					}
				}
			}
			(script(&layout, "webauthn"))
		}
	}

	fn get_title<'a>(&'a self, config: &'a Config) -> &'a str {
		&config.title
	}

	fn get_path_prefix<'a>(&'a self, config: &'a Config) -> &'a str {
		&config.path_prefix
	}
}

/// Helper function to create [`PageLayout`] from config
fn get_page_layout_from_config(config: &Config) -> PageLayout {
	let path_prefix = if config.path_prefix.ends_with('/') {
		&config.path_prefix[..config.path_prefix.len() - 1]
	} else {
		&config.path_prefix
	};

	PageLayout {
		title: config.title.clone(),
		path_prefix: path_prefix.to_string(),
	}
}
