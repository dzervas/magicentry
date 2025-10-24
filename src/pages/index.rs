//! Index page template (shown after successful login)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::partials::{script, PageLayout};
use crate::pages::Page;
use crate::config::ConfigFile;

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
	async fn render_partial(&self, config: &ConfigFile) -> Result<Markup, crate::pages::PageError> {
		let layout = get_page_layout_from_config(config);
		Ok(html! {
			div {
				p { (format!("Welcome back {}", self.email)) }
				p { "You're all set!" }
				a href="/logout" { "Logout" }
				button id="webauthn-register" { "Register PassKey" }
			}
			div {
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
			}
			(script(&layout, "webauthn"))
		})
	}

	fn get_title<'a>(&'a self, config: &'a ConfigFile) -> &'a str {
		&config.title
	}

	fn get_path_prefix<'a>(&'a self, config: &'a ConfigFile) -> &'a str {
		&config.path_prefix
	}
}

/// Helper function to create [`PageLayout`] from config
fn get_page_layout_from_config(config: &ConfigFile) -> PageLayout {
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
