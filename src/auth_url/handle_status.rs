use actix_web::cookie::Cookie;
use actix_web::{get, web, HttpRequest, HttpResponse};
use log::debug;

use crate::error::Response;
use crate::token::ScopedSessionToken;
use crate::{CONFIG, SCOPED_SESSION_COOKIE};

#[get("/auth-url/status")]
async fn status(req: HttpRequest, db: web::Data<reindeer::Db>) -> Response {
	let (token, cookie): (ScopedSessionToken, Option<Cookie<'_>>) =
		if let Ok(Some(token)) = ScopedSessionToken::from_session(&db, &req).await {
			debug!("Found scoped session from proxy cookie: {:?}", &token.code);
			(token, None)
		} else if let Ok(Some(token)) = ScopedSessionToken::from_proxy_cookie(&db, &req).await {
			let code = token.code.clone();
			debug!("Setting proxied cookie: {:?}", &code);
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
