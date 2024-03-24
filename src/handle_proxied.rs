use actix_session::Session;
use actix_web::cookie::Cookie;
use actix_web::http::{header, Uri};
use actix_web::{get, web, HttpRequest, HttpResponse};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::token::{ProxyCookieToken, ScopedSessionToken};
use crate::error::Result;
use crate::{CONFIG, PROXIED_COOKIE, SCOPED_SESSION_COOKIE};

fn get_request_origin(req: &HttpRequest) -> Result<String> {
	let valid_headers = [
		header::HeaderName::from_static("x-original-url"),
		header::ORIGIN,
		header::REFERER,
		// TODO: Is this correct? oauth2 proxy handles: https://github.com/oauth2-proxy/oauth2-proxy/issues/1607#issuecomment-1086889273
		header::HOST,
	];

	for header in valid_headers.iter() {
		if let Some(origin) = req.headers().get(header) {
			log::debug!("Origin header: {:?}", origin);
			let Ok(origin_str) = origin.to_str() else { continue; };
			let Ok(origin_uri) = origin_str.parse::<Uri>() else { continue; };
			let Some(origin_scheme) = origin_uri.scheme_str() else { continue; };
			let Some(origin_authority) = origin_uri.authority() else { continue; };

			return Ok(format!("{}://{}", origin_scheme, origin_authority));
		}
	}

	Err(AppErrorKind::MissingOriginHeader.into())
}

async fn new_from_proxy_cookie(db: &SqlitePool, req: &HttpRequest) -> Result<Option<ScopedSessionToken>> {
	let cookie = req.cookie(PROXIED_COOKIE).ok_or(AppErrorKind::MissingCookieHeader)?;

	let code = cookie.value();
	let token = ProxyCookieToken::from_code(db, code).await?;
	let metadata = token.metadata.clone().unwrap_or_default();
	let scope_parsed = metadata.parse::<Uri>().map_err(|_| AppErrorKind::InvalidRedirectUri)?;
	let scope_scheme = scope_parsed.scheme_str().ok_or(AppErrorKind::InvalidRedirectUri)?;
	let scope_authority = scope_parsed.authority().ok_or(AppErrorKind::InvalidRedirectUri)?;
	let scope_origin = format!("{}://{}", scope_scheme, scope_authority);
	let origin = get_request_origin(req)?;

	if origin != scope_origin {
		warn!("Invalid scope for proxy cookie: {} vs {}", &origin, &scope_origin);
		return Ok(None);
	}

	let scoped_session = ScopedSessionToken::new(
		db,
		&token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?,
		token.bound_to.clone(),
		Some(scope_origin)
	).await?;
	info!("New scoped session for: {}", &origin);

	Ok(Some(scoped_session))
}

async fn from_scoped_session(db: &SqlitePool, req: &HttpRequest) -> Result<Option<ScopedSessionToken>> {
	let origin = get_request_origin(req)?;

	if let Some(session_id) = req.cookie(SCOPED_SESSION_COOKIE) {
		let token = ScopedSessionToken::from_code(db, session_id.value()).await?;
		let metadata = token.metadata.clone().unwrap_or_default();
		let scope_parsed = metadata.parse::<Uri>().map_err(|_| AppErrorKind::InvalidRedirectUri)?;
		let scope_scheme = scope_parsed.scheme_str().ok_or(AppErrorKind::InvalidRedirectUri)?;
		let scope_authority = scope_parsed.authority().ok_or(AppErrorKind::InvalidRedirectUri)?;
		let scope_origin = format!("{}://{}", scope_scheme, scope_authority);

		if origin == scope_origin {
			return Ok(Some(token));
		}

		warn!("Invalid scope for scoped session: {} vs {}", origin, scope_origin);
	}

	Ok(None)
}

#[get("/proxied")]
async fn proxied(req: HttpRequest, db: web::Data<SqlitePool>) -> Response {
	let (token, cookie): (ScopedSessionToken, Option<Cookie>)  = if let Ok(Some(token)) = from_scoped_session(&db, &req).await {
		#[cfg(debug_assertions)]
		println!("Found scoped session from proxy cookie: {:?}", &token.code);
		(token, None)
	} else if let Ok(Some(token)) = new_from_proxy_cookie(&db, &req).await {
		let code = token.code.clone();
		#[cfg(debug_assertions)]
		println!("Setting proxied cookie: {:?}", &code);
		(token, Some(Cookie::build(SCOPED_SESSION_COOKIE, code)
			.path("/")
			.http_only(true)
			.secure(true)
			// .expires(expiry)
			.finish()))
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

	let mut response_builder = HttpResponse::Ok();
	let response = response_builder
		.insert_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
		.insert_header((CONFIG.auth_url_user_header.as_str(), user.username.unwrap_or_default()))
		.insert_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()));
		// TODO: Add realm
		// .insert_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")));

	if let Some(cookie) = cookie {
		Ok(response.cookie(cookie).finish())
	} else {
		Ok(response.finish())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProxiedRewrite {
	#[serde(rename = "__MAGICENTRY_CODE__")]
	pub(crate) code: String,
}

#[get("/proxied/rewrite")]
async fn proxied_rewrite(session: Session, db: web::Data<SqlitePool>, proxied_rewrite: web::Query<ProxiedRewrite>) -> Response {
	let code = &proxied_rewrite.code;

	let token = if let Ok(token) = ProxyCookieToken::from_code(&db, code).await {
		token
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let scoped_session = ScopedSessionToken::new(
		&db,
		&token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?,
		token.bound_to.clone(),
		token.metadata.clone()
	).await?;
	info!("New scoped session for: {:?}", &token.metadata);
	session.insert(SCOPED_SESSION_COOKIE, scoped_session.code)?;

	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

	Ok(HttpResponse::Ok()
		// TODO: Add realm
		.append_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
		.append_header((CONFIG.auth_url_user_header.as_str(), user.username.unwrap_or_default()))
		.append_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()))
		// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
		.finish())
}
