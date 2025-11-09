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
				// link rel="stylesheet" href="/static/main.css";
				// link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css";
				link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css";
			}
			body {
				main class="container" {
					(content)
				}

				footer class="container" {
					small {
						"Powered by ";
						a href="https://github.com/dzervas/magicentry" { "MagicEntry" }
						"."
					}
				}
			}
		}
	}
}

/// Script inclusion utility
#[must_use]
pub fn script(layout: &PageLayout, name: &str) -> Markup {
	html! {
		script src=(format!("{}/static/{}.js", layout.path_prefix, name)) type="module" {}
	}
}
