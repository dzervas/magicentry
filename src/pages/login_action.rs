//! Login action page template (shown after email is sent)

use maud::{Markup, html};
use crate::pages::partials::{render_page, PageLayout};

/// Login action page data
#[derive(Debug, Clone)]
pub struct LoginActionPage {
	pub title: String,
	pub path_prefix: String,
}

/// Render login action page
#[must_use]
pub fn render_login_action_page(page: &LoginActionPage) -> Markup {
	let layout = PageLayout {
		title: page.title.clone(),
		path_prefix: page.path_prefix.clone(),
	};

	let content = html! {
		p { "You're almost there" }
		p { "Check your email for the login link!" }
	};

	render_page(&layout, &content)
}
