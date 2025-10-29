use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use tracing::info;

use crate::config::LiveConfig;
use crate::error::AppError;
use crate::secret::{LoginLinkSecret, BrowserSessionSecret};
use crate::AppState;

#[derive(axum_extra::routing::TypedPath, serde::Deserialize)]
#[typed_path("/login/{link}")]
pub struct LoginPath {
	pub link: String,
}

#[axum::debug_handler]
pub async fn handle_magic_link(
	_: LoginPath,
	State(state): State<AppState>,
	config: LiveConfig,
	jar: CookieJar,
	login_secret: LoginLinkSecret,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
	info!("User {} logged in", &login_secret.user().email);
	let login_redirect_opt = login_secret.metadata().clone();
	let browser_session: BrowserSessionSecret = login_secret.exchange(&config, &state.db).await?;
	let cookie: Cookie<'static> = (&browser_session).into();

	// Handle post-login redirect URLs from the cookie set by OIDC/SAML/auth-url
	// These can be configured through either the service.<name>.auth_url.origins, service.<name>.saml.redirect_urls or service.<name>.oidc.redirect_urls
	// redirect_url = login_secret.redirect_url(&db).await?;
	let redirect_url = if let Some(login_redirect) = login_redirect_opt {
		login_redirect.into_redirect_url(Some(browser_session), &config, &state.db).await?
	} else {
		"/".to_string()
	};

	Ok((
		jar.add(cookie),
		Redirect::to(&redirect_url),
	))
}
