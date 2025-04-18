use actix_web::cookie::Cookie;
use actix_web::{get, web, HttpRequest, HttpResponse};
use log::debug;

use crate::error::Response;
use crate::token::ScopedSessionToken;
use crate::{CONFIG, SCOPED_SESSION_COOKIE};

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
async fn status(req: HttpRequest, db: web::Data<reindeer::Db>) -> Response {
	let (token, cookie): (ScopedSessionToken, Option<Cookie<'_>>) =
		if let Ok(Some(token)) = ScopedSessionToken::from_session(&db, &req).await {
			debug!("Found scoped session from proxy cookie: {:?}", &token.code);
			(token, None)
		} else if let Ok(Some(token)) = ScopedSessionToken::from_proxied_req(&db, &req).await {
			let code = token.code.clone();
			debug!("Found ephemeral proxy cookie: {:?}, turning it into a scoped session", &code);
			(
				token,
				Some(
					Cookie::build(SCOPED_SESSION_COOKIE, code)
						.path("/")
						.http_only(true)
						.secure(true)
						// .expires(expiry)
						.finish(),
				),
			)
		} else {
			return Ok(HttpResponse::Unauthorized().finish());
		};

	let mut response_builder = HttpResponse::Ok();
	let config = CONFIG.read().await;
	let response = response_builder
		.insert_header((
			config.auth_url_email_header.as_str(),
			token.user.email.clone(),
		))
		.insert_header((
			config.auth_url_user_header.as_str(),
			token.user.username.clone(),
		))
		.insert_header((
			config.auth_url_name_header.as_str(),
			token.user.name.clone(),
		))
		.insert_header((
			config.auth_url_realms_header.as_str(),
			token.user.realms.join(","),
		));

	if let Some(cookie) = cookie {
		Ok(response.cookie(cookie).finish())
	} else {
		Ok(response.finish())
	}
}
