use actix_web::cookie::Cookie;
use actix_web::{get, web, HttpResponse};
use axum::response::IntoResponse;
use tracing::info;

use crate::config::LiveConfig;
use crate::error::Response;
use crate::secret::ProxySessionSecret;
use crate::secret::ProxyCodeSecret;
use crate::{CONFIG, PROXY_SESSION_COOKIE};

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
#[get("/auth-url/status")]
async fn status(
	config: LiveConfig,
	db: web::Data<crate::Database>,
	proxy_code_opt: Option<ProxyCodeSecret>,
	proxy_session_opt: Option<ProxySessionSecret>,
) -> Response {
	let mut cookie = None;

	let proxy_session = if let Some(proxy_session) = proxy_session_opt {
		proxy_session
	} else if let Some(proxy_code) = proxy_code_opt {
		info!("Proxied login for {}", &proxy_code.user().email);
		let proxy_session: ProxySessionSecret = proxy_code
			.exchange_sibling(&config, &db)
			.await?;

		cookie = Some((&proxy_session).into());
		proxy_session
	} else {
		eprintln!("No proxy code or session");
		let mut remove_cookie = Cookie::new(PROXY_SESSION_COOKIE, "");
		remove_cookie.make_removal();

		return Ok(HttpResponse::Unauthorized()
			.cookie(remove_cookie)
			.finish());
	};

	let config = CONFIG.read().await;
	let mut response_builder = HttpResponse::Ok();
	let mut response = response_builder
		.content_type("text/plain")
		.insert_header((
			config.auth_url_email_header.as_str(),
			proxy_session.user().email.clone(),
		))
		.insert_header((
			config.auth_url_user_header.as_str(),
			proxy_session.user().username.clone(),
		))
		.insert_header((
			config.auth_url_name_header.as_str(),
			proxy_session.user().name.clone(),
		))
		.insert_header((
			config.auth_url_realms_header.as_str(),
			proxy_session.user().realms.join(","),
		));

	if let Some(cookie) = cookie {
		response = response.cookie(cookie);
	}
	drop(config);

	Ok(response.finish())
}

#[axum::debug_handler]
pub async fn handle_status(
	config: LiveConfig,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	mut jar: axum_extra::extract::CookieJar,
	proxy_code_opt: Option<ProxyCodeSecret>,
	proxy_session_opt: Option<ProxySessionSecret>,
) -> Result<(axum_extra::extract::CookieJar, axum::response::Response), crate::error::AppError> {
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
			axum::http::StatusCode::UNAUTHORIZED.into_response(),
		))
	};

	let mut headers = axum::http::HeaderMap::new();
	let user = proxy_session.user();

	// TODO: Add cache-control headers
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_email_header.as_bytes()).unwrap(),
		user.email.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_user_header.as_bytes()).unwrap(),
		user.username.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_name_header.as_bytes()).unwrap(),
		user.name.parse().unwrap(),
	);
	headers.insert(
		axum::http::header::HeaderName::from_bytes(config.auth_url_realms_header.as_bytes()).unwrap(),
		user.realms.join(",").parse().unwrap(),
	);

	Ok((
		jar,
		(headers, "OK").into_response(),
	))
}
