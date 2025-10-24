//! Page trait for async rendering with config integration

use maud::Markup;
use crate::pages::partials::render_page;
use crate::{CONFIG, config::ConfigFile};

/// Simple error type for page rendering
#[derive(Debug)]
pub struct PageError(String);

impl std::fmt::Display for PageError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Page error: {}", self.0)
	}
}

impl std::error::Error for PageError {}

impl From<&'static str> for PageError {
	fn from(msg: &'static str) -> Self {
		Self(msg.to_string())
	}
}

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
	async fn render_partial(&self, config: &ConfigFile) -> Result<Markup, PageError>;

	/// Render the complete HTML page with layout
	///
	/// This is a provided method that:
	/// 1. Gets the `title` and [`path_prefix`] from the global config
	/// 2. Calls [`render_partial`] with the config
	/// 3. Wraps the content in the full HTML page layout
	async fn render(&self) -> Result<Markup, PageError> {
		let config = CONFIG.read().await;
		let content = self.render_partial(&config).await?;
		let layout = crate::pages::partials::PageLayout {
			title: self.get_title(&config).to_string(),
			path_prefix: self.get_path_prefix(&config).to_string(),
		};

		drop(config);
		Ok(render_page(&layout, &content))
	}

	/// Get the page title from config or use a default
	/// This can be overridden by implementors for custom title logic
	fn get_title<'a>(&'a self, config: &'a ConfigFile) -> &'a str { &config.title }

	/// Get the path prefix from config or use a default
	/// This can be overridden by implementors for custom path prefix logic
	fn get_path_prefix<'a>(&'a self, config: &'a ConfigFile) -> &'a str { &config.path_prefix }
}
