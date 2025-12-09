//! Page layout utilities for maud templates

use maud::{DOCTYPE, Markup, html};

/// Page layout data for common page elements
#[derive(Debug, Clone)]
pub struct PageLayout {
	pub title: String,
	pub path_prefix: String,
}

/// Create a complete HTML page with content
#[must_use]
pub fn render_page(layout: &PageLayout, content: &Markup) -> Markup {
	html! {
		(DOCTYPE)
		html lang="en" {
			head {
				meta charset="UTF-8";
				meta name="viewport" content="width=device-width, initial-scale=1.0";
				meta name="color-scheme" content="light dark";
				title { (&layout.title) }
				link rel="stylesheet" href="/static/main.bundle.css";
			}
			body {
				section class="h-full bg-white dark:bg-gray-900" {
					main class="flex flex-col h-screen justify-center items-center" {
						(content)

						footer class="mx-auto max-w-(--breakpoint-sm) text-sm text-left text-gray-500 dark:text-gray-300 bottom-0 absolute my-6" {
							"Powered by ";
							a href="https://github.com/dzervas/magicentry" class="font-medium text-primary-600 dark:text-primary-500 hover:underline" { "MagicEntry" }
							"."
						}
					}
				}
			}
		}
	}
}

/// Script inclusion utility
pub fn script(name: &str) -> Markup {
	html! {
		script src=(format!("/static/{name}.js")) type="module" {}
	}
}
