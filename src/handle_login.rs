//! The login page endpoint handler - used to show the login page so that
//! unauthenticated users can log in using either a login link or webauthn
//!
//! If the user is already logged in, they'll get redirected to the index page
//! or the [`LoginLinkRedirect`], mainly used to handle auth-url/OIDC/SAML cases

use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};

use crate::config::LiveConfig;
use crate::error::Response;
use crate::secret::login_link::LoginLinkRedirect;
use crate::secret::BrowserSessionSecret;
use crate::pages::{LoginPage, Page};

#[get("/login")]
async fn login(
	config: LiveConfig,
	db: web::Data<crate::Database>,
	browser_session_opt: Option<BrowserSessionSecret>,
	web::Query(login_redirect): web::Query<LoginLinkRedirect>,
) -> Response {
	// Check if the user is already logged in
	if browser_session_opt.is_some() {
		// Already authorized, back to the index OR redirect to the service
		// Make sure that the redirect URL is valid (based on redirect_urls and origins)
		let Ok(redirect_url) = login_redirect.into_redirect_url(browser_session_opt, &config, &db).await else {
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
	let login_page = LoginPage.render().await;
	Ok(HttpResponse::Ok().content_type(ContentType::html()).body(login_page.into_string()))
}

use axum::response::IntoResponse;

#[axum::debug_handler]
pub async fn handle_login(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	axum::extract::Query(login_redirect): axum::extract::Query<LoginLinkRedirect>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
	// Check if the user is already logged in
	if browser_session_opt.is_some() {
		// Already authorized, back to the index OR redirect to the service
		// Make sure that the redirect URL is valid (based on redirect_urls and origins)
		let Ok(redirect_url) = login_redirect.into_redirect_url(browser_session_opt, &state.config.into(), &state.db).await else {
			// If not, back to index
			return Ok(axum::response::Redirect::temporary("/").into_response());
		};

		return Ok(axum::response::Redirect::temporary(&redirect_url).into_response());
	}

	// Unauthorized, show the login page
	let login_page = LoginPage.render().await;
	Ok(login_page.into_response())
}
