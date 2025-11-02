//! Error page template

use maud::{Markup, html};
use async_trait::async_trait;

use super::Page;
use super::partials::{PageLayout, render_page};

/// Error page data
#[derive(Debug, Clone)]
pub struct ErrorPage {
	pub code: String,
	pub error: String,
	pub description: String,
}

#[async_trait]
impl Page for ErrorPage {
	fn render_partial(&self) -> Markup {
		html! {
			h1 { (&self.code) }
			p { (&self.error) }
			p { (&self.description) }
			a href="/" { "Back to Homepage" }
		}
	}
}

impl ErrorPage {
	pub fn render_sync(code: u16, error: String, description: String) -> Markup {
		let page = Self {
			code: code.to_string(),
			error,
			description,
		};

		let content = page.render_partial();
		let layout = PageLayout {
			title: "MagicEntry Error".to_string(),
			path_prefix: "/".to_string(),
		};

		render_page(&layout, &content)
	}
}
