//! The index endpoint handler, used to render some basic data that regard the user
//!
//! It also shows the services that the user has access to

use axum::extract::State;
use axum::http::header::HeaderName;
use axum::http::HeaderMap;
use axum::response::IntoResponse;

use crate::secret::BrowserSessionSecret;
use crate::pages::{IndexPage, ServiceInfo, Page};
use crate::config::LiveConfig;
use crate::AppState;

#[axum::debug_handler]
pub async fn handle_index(
	config: LiveConfig,
	State(_state): State<AppState>,
	browser_session: BrowserSessionSecret,
) -> impl IntoResponse  {
	let realmed_services = config.services.from_user(browser_session.user());
	let services: Vec<ServiceInfo> = realmed_services.0.into_iter()
		.map(|service| ServiceInfo {
			name: service.name,
			url: service.url.to_string(),
		})
		.collect();
	let index_page = IndexPage {
		email: browser_session.user().email.clone(),
		services,
	}.render().await;

	let mut headers = HeaderMap::new();
	let user = browser_session.user();

	// TODO: Make the config store HeaderName instead of String or handle errors or have a user helper to return headers
	headers.insert(
		HeaderName::from_bytes(config.auth_url_email_header.as_bytes()).unwrap(),
		user.email.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_user_header.as_bytes()).unwrap(),
		user.username.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_name_header.as_bytes()).unwrap(),
		user.name.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_realms_header.as_bytes()).unwrap(),
		user.realms.join(",").parse().unwrap(),
	);

	(headers, index_page)
}
