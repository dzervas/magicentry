//! Login page template

use maud::{Markup, html};
use crate::pages::partials::{render_page, script, PageLayout};

/// Login page data
#[derive(Debug, Clone)]
pub struct LoginPage {
	pub title: String,
	pub path_prefix: String,
}

/// Render login page
#[must_use]
pub fn render_login_page(page: &LoginPage) -> Markup {
	let layout = PageLayout {
		title: page.title.clone(),
		path_prefix: page.path_prefix.clone(),
	};

	let content = html! {
		h2 { (format!("{} Login", page.title)) }
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
	};

	render_page(&layout, &content)
}
