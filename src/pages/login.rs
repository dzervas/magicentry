//! Login page template

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::Page;

/// Login page data
#[derive(Debug, Clone)]
pub struct LoginPage {
	pub title: String,
}

#[async_trait]
impl Page for LoginPage {
	fn render_partial(&self) -> Markup {
		html! {
			h2 { (self.title) }

			article {
				form action="" method="post" {
					fieldset role="group" {
						input
							type="email"
							name="email"
							required="required"
							autocomplete="email webauthn"
							placeholder="Enter your email" {}
						button id="webauthn-auth" type="button" class="secondary" { "PassKey" }
						button type="submit" { "Login" }
					}
				}
			}
			// TODO: Add webauthn back
			// (script(&layout, "webauthn"))
		}
	}
}
