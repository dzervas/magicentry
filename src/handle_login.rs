//! The login page endpoint handler - used to show the login page so that
//! unauthenticated users can log in using either a login link or webauthn
//!
//! If the user is already logged in, they'll get redirected to the index page
//! or the [`LoginLinkRedirect`], mainly used to handle auth-url/OIDC/SAML cases

use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};

use crate::error::Response;
use crate::secret::login_link::LoginLinkRedirect;
use crate::secret::BrowserSessionSecret;
use crate::pages::{LoginPage, Page};

#[get("/login")]
async fn login(
	db: web::Data<crate::Database>,
	browser_session_opt: Option<BrowserSessionSecret>,
	web::Query(login_redirect): web::Query<LoginLinkRedirect>,
) -> Response {
	// Check if the user is already logged in
	if browser_session_opt.is_some() {
		// Already authorized, back to the index OR redirect to the service
		// Make sure that the redirect URL is valid (based on redirect_urls and origins)
		let Ok(redirect_url) = login_redirect.into_redirect_url(browser_session_opt, &db).await else {
			// If not, back to index
			return Ok(HttpResponse::Found()
				.append_header(("Location", "/"))
				.finish());
		};

		return Ok(HttpResponse::Found()
			.append_header(("Location", redirect_url))
			.finish())
	}

	// Unauthorized, show the login page
	let login_page = LoginPage.render().await?;
	Ok(HttpResponse::Ok().content_type(ContentType::html()).body(login_page.into_string()))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_web::http::header::ContentType;
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_page() {
		let db = &db_connect().await;
		let app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login)
		)
		.await;

		let req = actix_test::TestRequest::get().uri("/login").to_request();

		let resp = actix_test::call_service(&app, req).await;
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
