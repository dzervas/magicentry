//! Login page template

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::partials::{script, PageLayout};
use crate::pages::Page;
use crate::config::ConfigFile;

/// Login page data
#[derive(Debug, Clone)]
pub struct LoginPage;

#[async_trait]
impl Page for LoginPage {
	async fn render_partial(&self, config: &ConfigFile) -> Result<Markup, crate::pages::PageError> {
		let layout = get_page_layout_from_config(config);
		Ok(html! {
			h2 { (format!("{} Login", config.title)) }
			form action="" method="post" {
				div {
					label for="email" { "Email address" }
					input
						type="email"
						id="email"
						name="email"
						required="required"
						autocomplete="email webauthn"
						placeholder="Enter your email" {}
				}
				div {
					button id="webauthn-auth" type="button" { "Passkey" }
				}
				div {
					button type="submit" { "Login" }
				}
			}
			(script(&layout, "webauthn"))
		})
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
