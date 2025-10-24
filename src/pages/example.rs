//! Example usage of the maud templates
//!
//! This file demonstrates how to use the new maud templates
//! and shows the migration path from handlebars.

use crate::pages::*;

/// Example: Rendering an error page using the new async Page trait
pub async fn example_error_page() -> Result<String, crate::pages::PageError> {
	let error_page = ErrorPage {
		code: "404".to_string(),
		error: "Not Found".to_string(),
		description: "The page you're looking for doesn't exist.".to_string(),
	};

	let html = error_page.render().await?;
	Ok(html.to_string())
	// Returns: String with complete HTML page using config values
}

/// Example: Using the legacy function (deprecated)
pub fn example_error_page_legacy() {
	let error_page = ErrorPage {
		code: "404".to_string(),
		error: "Not Found".to_string(),
		description: "The page you're looking for doesn't exist.".to_string(),
	};

	let _html = render_error_page(&error_page);
	// Returns: maud::Markup - DEPRECATED, use page.render() instead
}

/// Example: Rendering a login page using the new async Page trait
pub async fn example_login_page() -> Result<String, crate::pages::PageError> {
	let login_page = LoginPage;

	let html = login_page.render().await?;
	Ok(html.to_string())
	// Returns: String with complete HTML page using config.title for the title
}

/// Example: Using the legacy login page function (deprecated)
pub fn example_login_page_legacy() {
	let login_page = LoginPage;

	let _html = render_login_page(&login_page);
	// Returns: maud::Markup - DEPRECATED, use page.render() instead
}

/// Example: Rendering an index page with services using the new async Page trait
pub async fn example_index_page() -> Result<String, crate::pages::PageError> {
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
		],
	};

	let html = index_page.render().await?;
	Ok(html.to_string())
	// Returns: String with complete HTML page using config values
}

/// Example: Using the legacy index page function (deprecated)
pub fn example_index_page_legacy() {
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
		],
	};

	let _html = render_index_page(&index_page);
	// Returns: maud::Markup - DEPRECATED, use page.render() instead
}

/// Example: Rendering an authorization page using the new async Page trait
pub async fn example_authorize_page() -> Result<String, crate::pages::PageError> {
	let auth_page = AuthorizePage {
		client: "OAuthClient".to_string(),
		name: "John Doe".to_string(),
		username: "johndoe".to_string(),
		email: "john@example.com".to_string(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some("https://oauth.example.com/callback".to_string()),
	};

	let html = auth_page.render().await?;
	Ok(html.to_string())
	// Returns: String with complete HTML page using config values
}

/// Example: Using the legacy authorization page function (deprecated)
pub fn example_authorize_page_legacy() {
	let auth_page = AuthorizePage {
		client: "OAuthClient".to_string(),
		name: "John Doe".to_string(),
		username: "johndoe".to_string(),
		email: "john@example.com".to_string(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some("https://oauth.example.com/callback".to_string()),
	};

	let _html = render_authorize_page(&auth_page);
	// Returns: maud::Markup - DEPRECATED, use page.render() instead
}

/*
Migration Notes:
===============

1. Data Structure Changes:
   - From: BTreeMap<String, String> data + Option<T> state
   - To: Typed structs (ErrorPage, LoginPage, etc.)
   - Config values now come from global CONFIG at render time

2. Template Usage:
   - From: get_partial::<()>("template_name", data, None)?
   - To: page.render().await (async method)

3. Integration with Handlers:
   - Replace handlebars rendering calls with async maud template calls
   - Convert maud::Markup to String for HTTP responses:
	 let html_string = page.render().await?.to_string();
   - The Page trait provides both render_partial (with config access) and render (complete page)

4. Config Integration:
   - Title and path_prefix come from global CONFIG automatically
   - render_partial receives a RwLockReadGuard to the config
   - No need to manually pass config values to page structs

5. Benefits:
   - Compile-time HTML validation
   - Type safety with custom structs
   - Better performance (no template parsing at runtime)
   - Cleaner separation of concerns
   - Automatic config integration
   - Async rendering support
   - Better error handling with custom Error types

6. Backward Compatibility:
   - Legacy render_* functions are still available but deprecated
   - Gradual migration path from old to new API
*/
