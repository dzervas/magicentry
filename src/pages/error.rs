//! Error page template

use maud::{Markup, html};
use crate::pages::partials::{render_page, PageLayout};

/// Error page data
#[derive(Debug, Clone)]
pub struct ErrorPage {
	pub code: String,
	pub error: String,
	pub description: String,
	pub title: String,
	pub path_prefix: String,
}

/// Render error page
#[must_use]
pub fn render_error_page(page: &ErrorPage) -> Markup {
	let layout = PageLayout {
		title: page.title.clone(),
		path_prefix: page.path_prefix.clone(),
	};

	let content = html! {
		h1 { (&page.code) }
		p { (&page.error) }
		p { (&page.description) }
		a href=(format!("{}/", layout.path_prefix)) { "Back to Homepage" }
	};

	render_page(&layout, &content)
}
