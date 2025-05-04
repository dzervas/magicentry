use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use log::info;

use crate::error::Response;
use crate::user_secret::proxy_code::ProxyRedirectUrl;
use crate::user_secret::{BrowserSessionSecret, ProxyCodeSecret};
use crate::utils::get_partial;
use crate::{PROXY_QUERY_CODE, SESSION_COOKIE};

#[get("/login")]
async fn login_page(
	db: web::Data<reindeer::Db>,
	session: Session,
	proxy_redirect_opt: Option<web::Query<ProxyRedirectUrl>>,
) -> Response {
	// Check if the user is already logged in
	let browser_session = if let Ok(Some(session)) = session.get::<BrowserSessionSecret>(SESSION_COOKIE) {
		session.validate(&db).await?;
		session
	} else {
		// This is the same flow as explained below, but the user is unauthenticated,
		// so save the data to the session and let the index page handle the rest,
		// after the login.
		if let Some(proxy_redirect) = proxy_redirect_opt {
			session.insert(PROXY_QUERY_CODE, proxy_redirect.into_inner())?;
		}

		let login_page = get_partial::<()>("login", BTreeMap::new(), None)?;

		return Ok(HttpResponse::Ok()
			.content_type(ContentType::html())
			.body(login_page));
	};

	// Check if the request is a redirect from a proxy auth-url
	let proxy_redirect_url = if let Some(proxy_redirect) = proxy_redirect_opt {
		proxy_redirect.into_inner()
	} else {
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/"))
			.finish());
	};

	let proxy_code = ProxyCodeSecret::new_child(
		browser_session,
		proxy_redirect_url.clone(),
		&db,
	)
	.await?;

	// Redirect the user to the proxy but with an additional query secret (proxy_code)
	// so that we can identify them and hand them a proper partial session token.
	// The partial session token does not have access to the whole session
	// but only to the application that is being redirected to.
	//
	// Note that the proxy code will get forwarded to us from the proxy under a
	// different domain, so we can't just use a normal session cookie.

	// Log the pre-final redirect URL to avoid leaking the proxy code
	info!("Redirecting pre-authenticated user to proxy redirect url (destination) {}", &proxy_redirect_url.url);
	let final_redirect_url = proxy_code.final_redirect_url()?;

	Ok(HttpResponse::Found()
		.append_header(("Location", final_redirect_url.to_string()))
		.finish())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Key, SameSite};
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_page() {
		let db = &db_connect().await;
		let secret = Key::from(&[0; 64]);
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_page)
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
