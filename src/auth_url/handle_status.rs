use axum::extract::State;
use axum::http::header::HeaderName;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use tracing::info;

use crate::config::LiveConfig;
use crate::error::AppError;
use crate::secret::ProxySessionSecret;
use crate::secret::ProxyCodeSecret;
use crate::AppState;
use crate::PROXY_SESSION_COOKIE;

/// This endpoint is used to check weather a user is logged in from a proxy
/// running in a different domain.
/// It will return 200 only if the user is logged in and has a valid session.
/// It also returns some headers with user information, which can be used to
/// identify the user in the application.
/// It also handles the one-time-code passed from the login process and turns it
/// into a "scoped session", a session that is valid only for the given domain
/// so that the cookie can't be used to access other applications.
///
/// In order to use the one-time-code functionality, some setup is required,
/// documented in [the example](https://magicentry.rs/#/installation?id=example-valuesyaml)
#[axum::debug_handler]
pub async fn handle_status(
	config: LiveConfig,
	State(state): State<AppState>,
	mut jar: CookieJar,
	proxy_code_opt: Option<ProxyCodeSecret>,
	proxy_session_opt: Option<ProxySessionSecret>,
) -> Result<(CookieJar, Response), AppError> {
	let proxy_session = if let Some(proxy_session) = proxy_session_opt {
		proxy_session
	} else if let Some(proxy_code) = proxy_code_opt {
		info!("Proxied login for {}", &proxy_code.user().email);
		let proxy_session: ProxySessionSecret = proxy_code
			.exchange_sibling(&config, &state.db)
			.await?;

		jar = jar.add(&proxy_session);
		proxy_session
	} else {
		return Ok((
			jar.remove(PROXY_SESSION_COOKIE),
			StatusCode::UNAUTHORIZED.into_response(),
		))
	};

	let mut headers = HeaderMap::new();
	let user = proxy_session.user();

	// TODO: Add cache-control headers
	headers.insert(
		HeaderName::from_bytes(config.auth_url_email_header.as_bytes()).unwrap(),
		user.email.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_user_header.as_bytes()).unwrap(),
		user.username.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_name_header.as_bytes()).unwrap(),
		user.name.parse().unwrap(),
	);
	headers.insert(
		HeaderName::from_bytes(config.auth_url_realms_header.as_bytes()).unwrap(),
		user.realms.join(",").parse().unwrap(),
	);

	Ok((
		jar,
		(headers, "OK").into_response(),
	))
}
