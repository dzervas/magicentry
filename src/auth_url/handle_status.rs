use std::env;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::HeaderName;
use axum::response::IntoResponse;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use reqwest::header::COOKIE;
use tracing::{info, warn};

use crate::AppState;
use crate::OriginalUri;
use crate::PROXY_SESSION_COOKIE;
use crate::config::LiveConfig;
use crate::error::AppError;
use crate::secret::ProxyCodeSecret;
use crate::secret::ProxySessionSecret;
use crate::service::StatusAuth;

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
	request_headers: HeaderMap,
	proxy_code_opt: Option<ProxyCodeSecret>,
	proxy_session_opt: Option<ProxySessionSecret>,
	OriginalUri(origin_url): OriginalUri,
) -> Result<(CookieJar, Response), AppError> {
	let log_authurl_lines = env::var("LOG_AUTHURL_LINES")
		.map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true"))
		.unwrap_or(false);

	if log_authurl_lines {
		let cookies: Vec<&str> = jar
			.iter()
			.map(|cookie| cookie.name())
			.collect();
		let headers: Vec<&str> = request_headers
			.iter()
			.map(|(name, _value)| name.as_str())
			.collect();

		info!("authurl target: {}", origin_url);
		info!(
			"authurl cookies: {}",
			if cookies.is_empty() {
				"<none>".to_string()
			} else {
				cookies.join(", ")
			}
		);
		info!(
			"authurl headers: {}",
			if headers.is_empty() {
				"<none>".to_string()
			} else {
				headers.join(", ")
			}
		);
	}

	let proxy_session = if let Some(proxy_session) = proxy_session_opt {
		proxy_session
	} else if let Some(proxy_code) = proxy_code_opt {
		info!("Proxied login for {}", &proxy_code.user().email);
		let proxy_session: ProxySessionSecret =
			proxy_code.exchange_sibling(&config, &state.db).await?;

		jar = jar.add(&proxy_session);
		proxy_session
	} else {
		if let Some(service) = config.services.from_auth_url_origin(&origin_url.origin()) {
			if let Some(auth_url_cfg) = &service.auth_url {
				if let Some(status_url) = &auth_url_cfg.status_url {
					let mut cookie_names: Vec<&str> = Vec::new();

					if let Some(status_cookies) = &auth_url_cfg.status_cookies {
						cookie_names.extend(status_cookies.iter().map(String::as_str));
					}

					let mut cookie_header = None;

					if !cookie_names.is_empty() {
						let mut cookies: Vec<String> = Vec::new();

						for cookie_name in cookie_names {
							let Some(cookie) = jar.get(cookie_name) else {
								return Ok((
									jar.remove(PROXY_SESSION_COOKIE),
									StatusCode::UNAUTHORIZED.into_response(),
								));
							};

							cookies.push(format!("{cookie_name}={}", cookie.value()));
						}

						if !cookies.is_empty() {
							cookie_header = Some(cookies.join("; "));
						}
					}

					let client = reqwest::Client::new();
					let mut request = client.get(status_url.clone());

					if let Some(cookie_header) = cookie_header {
						request = request.header(COOKIE, cookie_header);
					}

					if let Some(headers) = &auth_url_cfg.status_headers {
						for header_name_str in headers {
							let Ok(name) = HeaderName::from_bytes(header_name_str.as_bytes())
							else {
								warn!(
									"Ignoring invalid status header name configured: {}",
									header_name_str
								);
								continue;
							};

							for value in request_headers.get_all(&name).iter() {
								request = request.header(name.clone(), value.clone());
							}
						}
					}

					if let Some(auth) = &auth_url_cfg.status_auth {
						request = match auth {
							StatusAuth::Basic { username, password } => {
								request.basic_auth(username, Some(password))
							}
							StatusAuth::Bearer { token } => request.bearer_auth(token),
						};
					}

					let response = request.send().await;

					let Ok(response) = response else {
						warn!("Could not get a response from upstream {status_url}");
						return Ok((
							jar.remove(PROXY_SESSION_COOKIE),
							StatusCode::UNAUTHORIZED.into_response(),
						));
					};

					if response.status() == StatusCode::OK {
						return Ok((jar, StatusCode::OK.into_response()));
					}
				}
			}
		}

		return Ok((
			jar.remove(PROXY_SESSION_COOKIE),
			StatusCode::UNAUTHORIZED.into_response(),
		));
	};

	let mut resp_headers = HeaderMap::new();
	let user = proxy_session.user();

	// TODO: Add cache-control headers
	resp_headers.insert(
		HeaderName::from_bytes(config.auth_url_email_header.as_bytes()).unwrap(),
		user.email.parse().unwrap(),
	);
	resp_headers.insert(
		HeaderName::from_bytes(config.auth_url_user_header.as_bytes()).unwrap(),
		user.username.parse().unwrap(),
	);
	resp_headers.insert(
		HeaderName::from_bytes(config.auth_url_name_header.as_bytes()).unwrap(),
		user.name.parse().unwrap(),
	);
	resp_headers.insert(
		HeaderName::from_bytes(config.auth_url_realms_header.as_bytes()).unwrap(),
		user.realms.join(",").parse().unwrap(),
	);

	Ok((jar, (resp_headers, "OK").into_response()))
}
