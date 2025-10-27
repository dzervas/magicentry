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
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session: BrowserSessionSecret,
) -> impl axum::response::IntoResponse  {
	let config: LiveConfig = state.config.into();
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

	// TODO: Return the headers
	// let mut headers = axum::http::HeaderMap::new();
	//
	// headers.insert(
	// 	config.auth_url_email_header.as_str(),
	// 	browser_session.user().email.parse().unwrap(),
	// );
	// headers.insert(
	// 	config.auth_url_user_header.as_str(),
	// 	browser_session.user().username.parse().unwrap(),
	// );
	// headers.insert(
	// 	config.auth_url_name_header.as_str(),
	// 	browser_session.user().name.parse().unwrap(),
	// );
	// headers.insert(
	// 	config.auth_url_realms_header.as_str(),
	// 	browser_session.user().realms.join(",").parse().unwrap(),
	// );

	// Ok(headers)
	axum::response::Html(index_page.into_string())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secret::LoginLinkSecret;
	use crate::utils::tests::*;
	use crate::{handle_magic_link};

	use actix_web::cookie::Cookie;
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, web, App};


	#[actix_web::test]
	async fn test_index() {
		let config = crate::CONFIG.read().await.clone().into();
		let db = &db_connect().await;
		let user = get_valid_user().await;

		let app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.service(handle_magic_link::magic_link)
		)
		.await;

		// Test unauthenticated request
		let req = actix_test::TestRequest::get().uri("/").to_request();
		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");

		// Generate a link
		let login_link = LoginLinkSecret::new(user, None, &config, db).await.unwrap();
		let login_link_url = login_link.get_login_url();
		eprintln!("Login link: {login_link_url}");

		// Visit valid generated link
		let req = actix_test::TestRequest::get()
			.uri(&login_link_url)
			.to_request();
		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/");

		// Set the returned cookie
		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		// Revisit the index to test authenticated request
		let req = actix_test::TestRequest::get()
			.uri("/")
			.cookie(parsed_cookie)
			.to_request();
		println!("req: {req:?}");
		let resp = actix_test::call_service(&app, req).await;
		println!("res: {resp:?}");
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(
			resp.headers()
				.get(config.auth_url_user_header.as_str())
				.unwrap(),
			"valid"
		);
		assert_eq!(
			resp.headers()
				.get(config.auth_url_email_header.as_str())
				.unwrap(),
			"valid@example.com"
		);

		// Test unauthenticated request again
		let req = actix_test::TestRequest::get().uri("/").to_request();
		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
