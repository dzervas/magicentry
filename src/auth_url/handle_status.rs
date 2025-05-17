use actix_web::cookie::Cookie;
use actix_web::{get, web, HttpResponse};
use log::info;

use crate::error::Response;
use crate::user_secret::ProxySessionSecret;
use crate::user_secret::ProxyCodeSecret;
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
/// documented in https://magicentry.rs/#/installation?id=example-valuesyaml
#[get("/auth-url/status")]
async fn status(
	db: web::Data<reindeer::Db>,
	proxy_code_opt: Option<ProxyCodeSecret>,
	proxy_session_opt: Option<ProxySessionSecret>,
) -> Response {
	let mut response_builder = HttpResponse::Ok();
	let mut response = response_builder.content_type("text/plain");

	let proxy_session = if let Some(proxy_session) = proxy_session_opt {
		proxy_session
	} else if let Some(proxy_code) = proxy_code_opt {
		info!("Proxied login for {}", &proxy_code.user().email);
		let proxy_session = proxy_code
			.exchange_sibling(&db)
			.await?;

		response = response.cookie(
			Cookie::build(PROXY_SESSION_COOKIE, proxy_session.code().to_str_that_i_wont_print())
				.path("/")
				.http_only(true)
				.finish(),
		);

		proxy_session
	} else {
		let mut remove_cookie = Cookie::new(PROXY_SESSION_COOKIE, "");
		remove_cookie.make_removal();
		remove_cookie.set_http_only(true);

		return Ok(HttpResponse::Unauthorized()
			.cookie(remove_cookie)
			.finish());
	};

	let config = CONFIG.read().await;
	response = response
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

	Ok(response.finish())
}
