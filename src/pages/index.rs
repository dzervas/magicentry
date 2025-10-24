//! Index page template (shown after successful login)

use maud::{Markup, html};
use crate::pages::partials::{render_page, script, PageLayout};

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
	pub title: String,
	pub path_prefix: String,
	pub services: Vec<ServiceInfo>,
}

/// Render index page
#[must_use]
pub fn render_index_page(page: &IndexPage) -> Markup {
	let layout = PageLayout {
		title: page.title.clone(),
		path_prefix: page.path_prefix.clone(),
	};

	let content = html! {
		div {
			p { (format!("Welcome back {}", page.email)) }
			p { "You're all set!" }
			a href="/logout" { "Logout" }
			button id="webauthn-register" { "Register PassKey" }
		}
		div {
			table {
				tbody {
					@for service in &page.services {
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
	};

	render_page(&layout, &content)
}
