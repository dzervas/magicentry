//! The index endpoint handler, used to render some basic data that regard the user
//!
//! It also shows the services that the user has access to

use std::collections::BTreeMap;

use actix_web::http::header::ContentType;
use actix_web::{get, HttpResponse};

use crate::error::Response;
use crate::secret::BrowserSessionSecret;
use crate::utils::get_partial;
use crate::CONFIG;

#[get("/")]
async fn index(
	browser_session: BrowserSessionSecret,
) -> Response {
	// Render the index page
	let config = CONFIG.read().await;
	let mut index_data = BTreeMap::new();
	index_data.insert("email", browser_session.user().email.clone());
	let realmed_services = config.services.from_user(&browser_session.user());
	let index_page = get_partial("index", index_data, Some(realmed_services))?;

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
		.body(index_page))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secret::LoginLinkSecret;
	use crate::utils::tests::*;
	use crate::{handle_magic_link, SESSION_COOKIE};

	use std::collections::HashMap;

	use actix_web::cookie::Cookie;
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, web, App};

	#[actix_web::test]
	async fn test_index() {
		let db = &db_connect().await;
		let mut session_map = HashMap::new();
		let user = get_valid_user().await;
		session_map.insert(SESSION_COOKIE, "valid_session_id");

		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.service(handle_magic_link::magic_link)
		)
		.await;

		// Test unauthenticated request
		let req = actix_test::TestRequest::get().uri("/").to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");

		// Generate a link
		let login_link = LoginLinkSecret::new(user, None, db).await.unwrap();

		// Visit valid generated link
		let req = actix_test::TestRequest::get()
			.uri(&login_link.get_login_url())
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
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
		println!("req: {:?}", req);
		let resp = actix_test::call_service(&mut app, req).await;
		println!("res: {:?}", resp);
		assert_eq!(resp.status(), StatusCode::OK);
		let config = CONFIG.read().await;
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
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
