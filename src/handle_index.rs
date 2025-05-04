use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use log::info;

use crate::error::Response;
use crate::user_secret::proxy_code::ProxyRedirectUrl;
use crate::user_secret::{BrowserSessionSecret, ProxyCodeSecret};
use crate::utils::get_partial;
use crate::{CONFIG, PROXY_QUERY_CODE, SESSION_COOKIE};

#[get("/")]
async fn index(
	db: web::Data<reindeer::Db>,
	session: Session,
) -> Response {
	let browser_session = if let Ok(Some(session)) = session.get::<BrowserSessionSecret>(SESSION_COOKIE) {
		println!("Session found: {:?}", session.user());
		session.validate(&db).await?;
		session
	} else {
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish());
	};

	if let Some(Ok(proxy_redirect_url)) = session.remove_as::<ProxyRedirectUrl>(PROXY_QUERY_CODE) {
		// Redirect the user to the proxy but with an additional query secret (proxy_code)
		// so that we can identify them and hand them a proper partial session token.
		// The partial session token does not have access to the whole session
		// but only to the application that is being redirected to.
		//
		// Note that the proxy code will get forwarded to us from the proxy under a
		// different domain, so we can't just use a normal session cookie.

		let proxy_code = ProxyCodeSecret::new_child(
			browser_session,
			proxy_redirect_url.clone(),
			&db,
		)
		.await?;

		info!("Redirecting newly authenticated user to proxy redirect url (destination) {}", &proxy_redirect_url.url);
		let final_redirect_url = proxy_code.final_redirect_url()?;

		return Ok(HttpResponse::Found()
			.append_header(("Location", final_redirect_url.to_string()))
			.finish());
	}

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
	use crate::user_secret::LoginLinkSecret;
	use crate::utils::tests::*;
	use crate::{handle_login_link, SESSION_COOKIE};

	use std::collections::HashMap;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Cookie, Key, SameSite};
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_index() {
		let db = &db_connect().await;
		let mut session_map = HashMap::new();
		let secret = Key::from(&[0; 64]);
		let user = get_valid_user().await;
		session_map.insert(SESSION_COOKIE, "valid_session_id");

		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.service(handle_login_link::login_link)
				.wrap(
					SessionMiddleware::builder(CookieSessionStore::default(), secret)
						.cookie_secure(false)
						.cookie_same_site(SameSite::Lax)
						.build(),
				),
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
