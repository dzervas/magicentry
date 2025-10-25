//! Error page template

use maud::{Markup, html};
use async_trait::async_trait;

use crate::config::Config;
use crate::CONFIG;

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
	fn render_partial(&self, _config: &Config) -> Markup {
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

		// TODO: I don't like this, but I'm not sure how to do it otherwise
		let mut i = 0;
		let config = loop {
			if let Ok(config) = CONFIG.try_read() {
				break config;
			}

			std::thread::sleep(std::time::Duration::from_millis(1));
			i += 1;
			// if i > 10 {
			// 	break render_page(&PageLayout {
			// 		title: "Error".to_string(),
			// 		path_prefix: "/".to_string(),
			// 	});
			// }
		};

		let content = page.render_partial(&config);
		let layout = PageLayout {
			title: page.get_title(&config).to_string(),
			path_prefix: page.get_path_prefix(&config).to_string(),
		};

		drop(config);

		render_page(&layout, &content)
	}
}
