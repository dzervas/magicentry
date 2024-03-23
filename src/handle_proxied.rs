use actix_session::Session;
use actix_web::cookie::Cookie;
use actix_web::http::{header, Uri};
use actix_web::{get, web, HttpRequest, HttpResponse};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::model::{Token, TokenKind};
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

async fn from_proxy_cookie(db: &SqlitePool, req: &HttpRequest, session: &Session) -> Result<Option<Token>> {
	let cookie_headers = req.headers()
		.get_all(header::COOKIE)
		.into_iter()
		.find(|h| {
			if let Ok(header) = h.to_str() {
				header.contains(PROXIED_COOKIE)
			} else {
				false
			}
		})
		.ok_or(AppErrorKind::MissingCookieHeader)?;
	let cookie_headers_str = cookie_headers
		.to_str()?
		.split("; ")
		.find(|c| c.starts_with(PROXIED_COOKIE))
		.ok_or(AppErrorKind::MissingCookieHeader)?;
	let parsed_cookies = Cookie::parse_encoded(cookie_headers_str)?;
	println!("{:?}", parsed_cookies);

	if parsed_cookies.name() != PROXIED_COOKIE {
		return Ok(None);
	}
	let code = parsed_cookies.value();
	let token = Token::from_code(db, code, TokenKind::ProxyCookie).await?;
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

	let scoped_session = Token::new(
		db,
		TokenKind::ScopedSession,
		&token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?,
		token.bound_to.clone(),
		token.metadata.clone()
	).await?;
	info!("New scoped session for: {}", &metadata);
	session.insert(SCOPED_SESSION_COOKIE, scoped_session.code)?;

	Ok(Some(token))
}

async fn from_scoped_session(db: &SqlitePool, req: &HttpRequest, session: &Session) -> Result<Option<Token>> {
	let origin = get_request_origin(req)?;

	if let Some(session_id) = session.get::<String>(SCOPED_SESSION_COOKIE).unwrap_or(None) {
		let token = Token::from_code(db, session_id.as_str(), TokenKind::ScopedSession).await?;
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

	session.remove(SCOPED_SESSION_COOKIE);
	Ok(None)
}

#[get("/proxied")]
async fn proxied(req: HttpRequest, session: Session, db: web::Data<SqlitePool>) -> Response {
	let token = if let Ok(Some(token)) = from_scoped_session(&db, &req, &session).await {
		token
	} else if let Ok(Some(token)) = from_proxy_cookie(&db, &req, &session).await {
		token
	} else {
		#[cfg(debug_assertions)]
		log::debug!("Neither proxy cookie nor scoped session found");
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

	Ok(HttpResponse::Ok()
		// TODO: Add realm
		.append_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
		.append_header((CONFIG.auth_url_user_header.as_str(), user.username.unwrap_or_default()))
		.append_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()))
		// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
		.finish())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProxiedRewrite {
	#[serde(rename = "__MAGICENTRY_CODE__")]
	pub(crate) code: String,
}

#[get("/proxied/rewrite")]
async fn proxied_rewrite(session: Session, db: web::Data<SqlitePool>, proxied_rewrite: web::Query<ProxiedRewrite>) -> Response {
	let code = &proxied_rewrite.code;

	let token = if let Ok(token) = Token::from_code(&db, code, TokenKind::ProxyCookie).await {
		token
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let scoped_session = Token::new(
		&db,
		TokenKind::ScopedSession,
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
