//! Error page template

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::Page;
use crate::config::ConfigFile;

/// Error page data
#[derive(Debug, Clone)]
pub struct ErrorPage {
	pub code: String,
	pub error: String,
	pub description: String,
}

#[async_trait]
impl Page for ErrorPage {
	async fn render_partial(&self, _config: &ConfigFile) -> Result<Markup, crate::pages::PageError> {
		Ok(html! {
			h1 { (&self.code) }
			p { (&self.error) }
			p { (&self.description) }
			a href="/" { "Back to Homepage" }
		})
	}
}
