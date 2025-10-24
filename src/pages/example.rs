//! Example usage of the maud templates
//!
//! This file demonstrates how to use the new maud templates
//! and shows the migration path from handlebars.

use crate::pages::*;

/// Example: Rendering an error page
pub fn example_error_page() {
	let error_page = ErrorPage {
		code: "404".to_string(),
		error: "Not Found".to_string(),
		description: "The page you're looking for doesn't exist.".to_string(),
		title: "Error".to_string(),
		path_prefix: "".to_string(),
	};

	let _html = render_error_page(&error_page);
	// Returns: maud::Markup that can be converted to String for HTTP responses
}

/// Example: Rendering a login page
pub fn example_login_page() {
	let login_page = LoginPage {
		title: "MyApp".to_string(),
		path_prefix: "".to_string(),
	};

	let _html = render_login_page(&login_page);
	// Returns: complete HTML page with login form
}

/// Example: Rendering an index page with services
pub fn example_index_page() {
	let index_page = IndexPage {
		email: "user@example.com".to_string(),
		title: "MyApp".to_string(),
		path_prefix: "".to_string(),
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
	// Returns: complete HTML page with user info and service list
}

/// Example: Rendering an authorization page
pub fn example_authorize_page() {
	let auth_page = AuthorizePage {
		client: "OAuthClient".to_string(),
		name: "John Doe".to_string(),
		username: "johndoe".to_string(),
		email: "john@example.com".to_string(),
		path_prefix: "".to_string(),
		title: "Authorize".to_string(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some("https://oauth.example.com/callback".to_string()),
	};

	let _html = render_authorize_page(&auth_page);
	// Returns: complete HTML page with authorization consent
}

/*
Migration Notes:
===============

1. Data Structure Changes:
   - From: BTreeMap<String, String> data + Option<T> state
   - To: Typed structs (ErrorPage, LoginPage, etc.)

2. Template Usage:
   - From: get_partial::<()>("template_name", data, None)?
   - To: render_template_name(&template_struct)

3. Integration with Handlers:
   - Replace handlebars rendering calls with maud template calls
   - Convert maud::Markup to String for HTTP responses:
	 let html_string = template_result.to_string();

4. Benefits:
   - Compile-time HTML validation
   - Type safety with custom structs
   - Better performance (no template parsing at runtime)
   - Cleaner separation of concerns
*/
