//! Login action page template (shown after email is sent)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::Page;

/// Login action page data
#[derive(Debug, Clone)]
pub struct LoginActionPage;

#[async_trait]
impl Page for LoginActionPage {
	fn render_partial(&self) -> Markup {
		html! {
			section {
				h3 { "You're almost there!" }
				p { "Check your email for the login link" }
			}
		}
	}
}
