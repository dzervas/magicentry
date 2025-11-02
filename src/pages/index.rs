//! Index page template (shown after successful login)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::Page;

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
	fn render_partial(&self) -> Markup {
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
									img src=("/static/app-placeholder.svg") {}
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
			//(script(&layout, "webauthn"))
		}
	}
}
