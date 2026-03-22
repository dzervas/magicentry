//! Example: Render all pages to HTML files
//!
//! This example demonstrates how to use the Page trait to render all
//! page types and export them as HTML files for inspection.

use anyhow::Context;
use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::error::AppError;
use crate::pages::*;

/// Helper function to render pages with mock config
fn render_with_mock_config<P: Page>(page: &P, filename: &str) -> Result<(), AppError> {
	// For this example, we'll simulate the global CONFIG with a local Arc<RwLock>
	// In a real application, the global CONFIG would be properly initialized

	// Create a mock config and use it directly with render_partial
	let mock_config = Config::default();

	// Manually implement the render logic using the mock config
	let content = page.render_partial();

	// Create layout and render full page
	let layout = crate::pages::partials::PageLayout {
		title: page.get_title(&mock_config).to_string(),
		path_prefix: page.get_path_prefix(&mock_config).to_string(),
	};

	let html = crate::pages::partials::render_page(&layout, &content);
	save_html(filename, &html.into_string()).context("Failed to save HTML file")?;

	Ok(())
}

/// Create output directory
fn ensure_output_dir() -> Result<(), std::io::Error> {
	let output_dir = Path::new("rendered_pages");
	if output_dir.exists() {
		fs::remove_dir_all(output_dir)?;
	}
	fs::create_dir_all(output_dir)?;
	Ok(())
}

/// Save HTML content to file
fn save_html(filename: &str, content: &str) -> Result<(), std::io::Error> {
	let filepath = Path::new("rendered_pages").join(filename);
	fs::write(filepath, content)?;
	println!("✅ Saved: {filename}");
	Ok(())
}

/// Render and save error page
fn render_error_page() -> Result<(), AppError> {
	let error_page = ErrorPage {
		code: "404".to_string(),
		error: "Page Not Found".to_string(),
		description: "The page you're looking for doesn't exist.".to_string(),
	};

	render_with_mock_config(&error_page, "error.html")
}

/// Render and save login page
fn render_login_page() -> Result<(), AppError> {
	let login_page = LoginPage {
		title: "Login".to_string(),
	};

	render_with_mock_config(&login_page, "login.html")
}

/// Render and save login action page
fn render_login_action_page() -> Result<(), AppError> {
	let login_action_page = LoginActionPage;

	render_with_mock_config(&login_action_page, "login_action.html")
}

/// Render and save index page
fn render_index_page() -> Result<(), AppError> {
	let index_page = IndexPage {
		email: "user@example.com".to_string(),
		services: vec![
			ServiceInfo {
				name: "Service 1".to_string(),
				url: "https://service1.example.com".to_string(),
			},
			ServiceInfo {
				name: "Service 2".to_string(),
				url: "https://service2.example.com".to_string(),
			},
			ServiceInfo {
				name: "Internal Dashboard".to_string(),
				url: "https://dashboard.example.com".to_string(),
			},
		],
	};

	render_with_mock_config(&index_page, "index.html")
}

/// Render and save authorization page (OIDC)
fn render_authorize_page_oidc() -> Result<(), AppError> {
	let auth_page = AuthorizePage {
		client: "OAuth Client".to_string(),
		name: "John Doe".to_string(),
		username: "johndoe".to_string(),
		email: "john@example.com".to_string(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some("https://oauth.example.com/callback?code=abc123&state=xyz789".to_string()),
	};

	render_with_mock_config(&auth_page, "authorize_oidc.html")
}

/// Render and save authorization page (SAML)
fn render_authorize_page_saml() -> Result<(), AppError> {
	let auth_page = AuthorizePage {
		client: "SAML Service Provider".to_string(),
		name: "Jane Smith".to_string(),
		username: "janesmith".to_string(),
		email: "jane@example.com".to_string(),
		saml_response_data: Some("PHNhbWxQYXJhbWV0ZXMgU3RhdHVzPSJTdWNjZXNzIiB8IEB4bWwgc3RhdGljIGRlY2xhcmF0aW9ucz0iZWFzeSI+PC9zYW1sUGFyYW1ldGVycz4=".to_string()), // Mock SAML response
		saml_relay_state: Some("relay_state_123".to_string()),
		saml_acs: Some("https://saml.example.com/saml/acs".to_string()),
		link: None,
	};

	render_with_mock_config(&auth_page, "authorize_saml.html")
}

#[tokio::test]
async fn render_pages() {
	ensure_output_dir().unwrap();

	render_error_page().unwrap();
	render_login_page().unwrap();
	render_login_action_page().unwrap();
	render_index_page().unwrap();
	render_authorize_page_oidc().unwrap();
	render_authorize_page_saml().unwrap();
}
