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
			div class="py-8 px-4 mx-auto max-w-(--breakpoint-xl) lg:py-16 lg:px-6" {
				div class="mx-auto max-w-(--breakpoint-sm) text-center" {
					h1 class="mb-4 text-7xl tracking-tight font-extrabold lg:text-9xl text-primary-600 dark:text-primary-500" {
						(&self.code)
					}
					p class="mb-4 text-3xl tracking-tight font-bold text-gray-900 md:text-4xl dark:text-white" { (&self.error) }
					p class="mb-4 text-lg font-light text-gray-500 dark:text-gray-400" { (&self.description) }
					a href="/" class="inline-flex text-white bg-primary-600 hover:bg-primary-800 focus:ring-4 focus:outline-hidden focus:ring-primary-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:focus:ring-primary-900 my-4" { "Back to Homepage" }
				}
			}
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
