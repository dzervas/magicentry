//! Page trait for async rendering with config integration

use maud::Markup;
use crate::{CONFIG, config::ConfigFile};

use super::partials::{PageLayout, render_page};

/// Trait for page types that can render themselves
///
/// This trait provides a common interface for all page types to:
/// 1. Render their content with access to the global config
/// 2. Provide a complete HTML page with proper layout
#[async_trait::async_trait]
pub trait Page {
	/// Render the partial content of the page with config access
	///
	/// This method receives config data and should
	/// render only the page content (without the full HTML structure)
	fn render_partial(&self, config: &ConfigFile) -> Markup;

	/// Render the complete HTML page with layout
	///
	/// This is a provided method that:
	/// 1. Gets the `title` and [`path_prefix`] from the global config
	/// 2. Calls [`render_partial`] with the config
	/// 3. Wraps the content in the full HTML page layout
	async fn render(&self) -> Markup {
		let config = CONFIG.read().await;
		let content = self.render_partial(&config);
		let layout = PageLayout {
			title: self.get_title(&config).to_string(),
			path_prefix: self.get_path_prefix(&config).to_string(),
		};

		drop(config);
		render_page(&layout, &content)
	}

	/// Get the page title from config or use a default
	/// This can be overridden by implementors for custom title logic
	fn get_title<'a>(&'a self, config: &'a ConfigFile) -> &'a str { &config.title }

	/// Get the path prefix from config or use a default
	/// This can be overridden by implementors for custom path prefix logic
	fn get_path_prefix<'a>(&'a self, config: &'a ConfigFile) -> &'a str { &config.path_prefix }
}
