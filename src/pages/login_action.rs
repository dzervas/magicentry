//! Login action page template (shown after email is sent)

use maud::{Markup, html};
use async_trait::async_trait;
use crate::pages::Page;
use crate::config::ConfigFile;

/// Login action page data
#[derive(Debug, Clone)]
pub struct LoginActionPage;

#[async_trait]
impl Page for LoginActionPage {
	async fn render_partial(&self, _config: &ConfigFile) -> Result<Markup, crate::pages::PageError> {
		Ok(html! {
			p { "You're almost there" }
			p { "Check your email for the login link!" }
		})
	}
}
