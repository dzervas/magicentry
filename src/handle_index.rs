//! The index endpoint handler, used to render some basic data that regard the user
//!
//! It also shows the services that the user has access to

use actix_web::http::header::ContentType;
use actix_web::{get, HttpResponse};

use crate::error::Response;
use crate::secret::BrowserSessionSecret;
use crate::pages::{IndexPage, ServiceInfo, Page};
use crate::config::LiveConfig;

#[get("/")]
async fn index(
	browser_session: BrowserSessionSecret,
	config: LiveConfig,
) -> Response {
	// Render the index page
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

	// Respond with the index page and set the X-Remote headers as configured
	Ok(HttpResponse::Ok()
		.append_header((
			config.auth_url_email_header.as_str(),
			browser_session.user().email.clone(),
		))
		.append_header((
			config.auth_url_user_header.as_str(),
			browser_session.user().username.clone(),
		))
		.append_header((
			config.auth_url_name_header.as_str(),
			browser_session.user().name.clone(),
		))
		.append_header((
			config.auth_url_realms_header.as_str(),
			browser_session.user().realms.join(","),
		))
		.content_type(ContentType::html())
		.body(index_page.into_string()))
}

#[axum::debug_handler]
pub async fn handle_index(
	config: LiveConfig,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session: BrowserSessionSecret,
) -> impl axum::response::IntoResponse  {
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

	let mut headers = axum::http::HeaderMap::new();
	let user = browser_session.user();

	// TODO: Make the config store HeaderName instead of String or handle errors or have a user helper to return headers
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_email_header.as_bytes()).unwrap(),
		user.email.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_user_header.as_bytes()).unwrap(),
		user.username.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_name_header.as_bytes()).unwrap(),
		user.name.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_realms_header.as_bytes()).unwrap(),
		user.realms.join(",").parse().unwrap(),
	);

	(headers, index_page)
}
