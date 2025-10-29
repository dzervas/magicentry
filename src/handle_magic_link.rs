use actix_web::http::header;
use actix_web::{get, web, HttpResponse};
use tracing::info;

use crate::config::LiveConfig;
use crate::error::Response;
use crate::secret::{LoginLinkSecret, BrowserSessionSecret};

#[get("/login/{magic}")]
async fn magic_link(
	config: LiveConfig,
	login_secret: LoginLinkSecret,
	db: web::Data<crate::Database>,
) -> Response {
	info!("User {} logged in", &login_secret.user().email);
	let login_redirect_opt = login_secret.metadata().clone();
	let browser_session: BrowserSessionSecret = login_secret.exchange(&config, &db).await?;
	let cookie = (&browser_session).into();

	// Handle post-login redirect URLs from the cookie set by OIDC/SAML/auth-url
	// These can be configured through either the service.<name>.auth_url.origins, service.<name>.saml.redirect_urls or service.<name>.oidc.redirect_urls
	// redirect_url = login_secret.redirect_url(&db).await?;
	let redirect_url = if let Some(login_redirect) = login_redirect_opt {
		login_redirect.into_redirect_url(Some(browser_session), &config, &db).await?
	} else {
		"/".to_string()
	};

	Ok(HttpResponse::Found()
		.append_header((header::LOCATION, redirect_url))
		.cookie(cookie)
		.finish())
}

#[derive(axum_extra::routing::TypedPath, serde::Deserialize)]
#[typed_path("/login/{link}")]
pub struct LoginPath {
	pub link: String,
}

#[axum::debug_handler]
pub async fn handle_magic_link(
	_: LoginPath,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	jar: axum_extra::extract::CookieJar,
	login_secret: LoginLinkSecret,
) -> Result<(axum_extra::extract::CookieJar, impl axum::response::IntoResponse), crate::error::AppError> {
	info!("User {} logged in", &login_secret.user().email);
	let config = state.config.into();
	let login_redirect_opt = login_secret.metadata().clone();
	let browser_session: BrowserSessionSecret = login_secret.exchange(&config, &state.db).await?;
	let cookie: axum_extra::extract::cookie::Cookie<'static> = (&browser_session).into();

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
		axum::response::Redirect::temporary(&redirect_url),
	))
}
