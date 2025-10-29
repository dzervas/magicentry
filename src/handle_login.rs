//! The login page endpoint handler - used to show the login page so that
//! unauthenticated users can log in using either a login link or webauthn
//!
//! If the user is already logged in, they'll get redirected to the index page
//! or the [`LoginLinkRedirect`], mainly used to handle auth-url/OIDC/SAML cases

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::LiveConfig;
use crate::secret::login_link::LoginLinkRedirect;
use crate::secret::BrowserSessionSecret;
use crate::pages::{LoginPage, Page};
use crate::AppState;

#[axum::debug_handler]
pub async fn handle_login(
	config: LiveConfig,
	State(state): State<AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	Query(login_redirect): Query<LoginLinkRedirect>,
) -> Result<Response, StatusCode> {
	// Check if the user is already logged in
	if browser_session_opt.is_some() {
		// Already authorized, back to the index OR redirect to the service
		// Make sure that the redirect URL is valid (based on redirect_urls and origins)
		let Ok(redirect_url) = login_redirect.into_redirect_url(browser_session_opt, &config, &state.db).await else {
			// If not, back to index
			return Ok(Redirect::to("/").into_response());
		};

		return Ok(Redirect::to(&redirect_url).into_response());
	}

	// Unauthorized, show the login page
	let login_page = LoginPage.render().await;
	Ok(login_page.into_response())
}
