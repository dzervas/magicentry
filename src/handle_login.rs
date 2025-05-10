use std::collections::BTreeMap;

use actix_web::{get, web, HttpResponse};

use crate::error::Response;
use crate::user_secret::login_link::LoginLinkRedirect;
use crate::user_secret::BrowserSessionSecret;
use crate::utils::get_partial;

#[get("/login")]
async fn login(
	db: web::Data<reindeer::Db>,
	browser_session_opt: Option<BrowserSessionSecret>,
	login_redirect_opt: web::Query<Option<LoginLinkRedirect>>,
) -> Response {
	// Check if the user is already logged in
	if browser_session_opt.is_some() {
		// Already authorized, back to the index OR redirect to the service
		// Check if the request has redirect query parameters
		let Some(login_redirect) = login_redirect_opt.into_inner() else {
			return Ok(HttpResponse::Found()
				.append_header(("Location", "/"))
				.finish());
		};

		// Make sure that the redirect URL is valid (based on redirect_urls and origins)
		let login_redirect_url = login_redirect
			.into_redirect_url(browser_session_opt, &db).await?
			.to_string();

		return Ok(HttpResponse::Found()
			.append_header(("Location", login_redirect_url))
			.finish())
	}

	// Unauthorized, show the login page
	let login_page = get_partial::<()>("login", BTreeMap::new(), None)?;
	Ok(HttpResponse::Ok().body(login_page))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Key, SameSite};
	use actix_web::http::header::ContentType;
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_page() {
		let db = &db_connect().await;
		let secret = Key::from(&[0; 64]);
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login)
				.wrap(
					SessionMiddleware::builder(CookieSessionStore::default(), secret)
						.cookie_secure(false)
						.cookie_same_site(SameSite::Lax)
						.build(),
				),
		)
		.await;

		let req = actix_test::TestRequest::get().uri("/login").to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(
			resp.headers()
				.get("Content-Type")
				.unwrap()
				.to_str()
				.unwrap(),
			ContentType::html().to_string().as_str()
		);
	}
}
