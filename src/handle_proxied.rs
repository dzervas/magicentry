use actix_session::Session;
use actix_web::cookie::Cookie;
use actix_web::http::{header, Uri};
use actix_web::{get, web, HttpRequest, HttpResponse};
use log::warn;
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::model::{Token, TokenKind};
use crate::error::Result;
use crate::{CONFIG, PROXIED_COOKIE, SCOPED_SESSION_COOKIE};

async fn from_proxy_cookie(db: &SqlitePool, req: &HttpRequest, session: &Session) -> Result<Option<Token>> {
	let cookie_headers = req.headers().get(header::COOKIE).ok_or(AppErrorKind::MissingCookieHeader)?;
	let cookie_headers_str = cookie_headers.to_str()?;
	let parsed_cookies = Cookie::parse_encoded(cookie_headers_str)?;

	if parsed_cookies.name() != PROXIED_COOKIE {
		return Ok(None);
	}
	let code = parsed_cookies.value();
	let token = Token::from_code(db, code, TokenKind::ProxyCookie).await?;
	let metadata = token.metadata.clone().unwrap_or_default();
	let scope_parsed = metadata.parse::<Uri>().map_err(|_| AppErrorKind::InvalidRedirectUri)?;
	let scope_authority = scope_parsed.authority().ok_or(AppErrorKind::InvalidRedirectUri)?;

	if req.connection_info().host() != scope_authority.as_str() {
		warn!("Invalid scope for proxy cookie: {}", metadata);
		return Ok(None);
	}

	let scoped_session = Token::new(
		db,
		TokenKind::ScopedSession,
		&token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?,
		token.bound_to.clone(),
		token.metadata.clone()
	).await?;
	println!("Scoped session: {:?}", scoped_session);
	session.insert(SCOPED_SESSION_COOKIE, scoped_session.code)?;

	Ok(Some(token))
}

async fn from_scoped_session(db: &SqlitePool, req: &HttpRequest, session: &Session) -> Result<Option<Token>> {
	let conn_info = req.connection_info();
	let host = conn_info.host();

	if let Some(session_id) = session.get::<String>(SCOPED_SESSION_COOKIE).unwrap_or(None) {
		let token = Token::from_code(db, session_id.as_str(), TokenKind::ScopedSession).await?;
		let metadata = token.metadata.clone().unwrap_or_default();
		let scope_parsed = metadata.parse::<Uri>().map_err(|_| AppErrorKind::InvalidRedirectUri)?;
		let scope_authority = scope_parsed.authority().ok_or(AppErrorKind::InvalidRedirectUri)?;

		println!("{} != {}", host, scope_authority);
		if host == scope_authority.as_str() {
			return Ok(Some(token));
		}
	}

	warn!("Invalid scope for scoped session: {}", host);
	session.remove(SCOPED_SESSION_COOKIE);
	Ok(None)
}

#[get("/proxied")]
async fn proxied(req: HttpRequest, session: Session, db: web::Data<SqlitePool>) -> Response {
	let token = if let Ok(Some(token)) = from_proxy_cookie(&db, &req, &session).await {
		token
	} else if let Ok(Some(token)) = from_scoped_session(&db, &req, &session).await {
		token
	} else {
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
