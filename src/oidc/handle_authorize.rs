use std::collections::BTreeMap;

use actix_web::cookie::Cookie;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use log::info;

use crate::error::{AppErrorKind, Response};
use crate::user_secret::{BrowserSessionSecret, OIDCAuthCodeSecret};
use crate::utils::get_partial;
use crate::{AUTHORIZATION_COOKIE, CONFIG};

use super::AuthorizeRequest;

async fn authorize(
	req: HttpRequest,
	db: web::Data<crate::Database>,
	auth_req: AuthorizeRequest,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> Response {
	info!("Beginning OIDC flow for {}", auth_req.client_id);

	let Some(browser_session) = browser_session_opt else {
		let config = CONFIG.read().await;
		let base_url = config.url_from_request(&req);
		let target_url = format!("{}/login?{}", base_url, serde_qs::to_string(&auth_req)?);
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish());
	};

	// let oidc_authcode = auth_req
	// 	.generate_session_code(&db, browser_session.user().clone(), browser_session.code())
	// 	.await?;
	let oidc_authcode = OIDCAuthCodeSecret::new_child(browser_session, auth_req.clone(), &db).await?;

	// TODO: Check the state with the cookie for CSRF
	// TODO: WTF?
	let redirect_url = auth_req
		.get_redirect_url(&oidc_authcode.code().to_str_that_i_wont_print(), &oidc_authcode.user())
		.await
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_uri = redirect_url.parse::<Uri>()?;
	let redirect_url_scheme = redirect_url_uri
		.scheme_str()
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_authority = redirect_url_uri
		.authority()
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_str = format!("{}://{}", redirect_url_scheme, redirect_url_authority);

	let mut authorize_data = BTreeMap::new();
	authorize_data.insert("name", oidc_authcode.user().name.clone());
	authorize_data.insert("username", oidc_authcode.user().username.clone());
	authorize_data.insert("email", oidc_authcode.user().email.clone());
	authorize_data.insert("client", redirect_url_str.clone());
	authorize_data.insert("link", redirect_url.clone());
	let authorize_page = get_partial::<()>("authorize", authorize_data, None)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.cookie(Cookie::new(AUTHORIZATION_COOKIE, serde_json::to_string(&auth_req)?))
		.body(authorize_page))
	// Either send to ?code=<code>&state=<state>
	// TODO: Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(
	req: HttpRequest,
	db: web::Data<crate::Database>,
	data: web::Query<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(req, db, data.into_inner(), browser_session_opt).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(
	req: HttpRequest,
	db: web::Data<crate::Database>,
	data: web::Form<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(req, db, data.into_inner(), browser_session_opt).await
}
