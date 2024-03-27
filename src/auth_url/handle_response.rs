use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use log::info;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::token::{ProxyCookieToken, ScopedSessionToken};
use crate::{CONFIG, SCOPED_SESSION_COOKIE};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProxiedRewrite {
	#[serde(rename = "__MAGICENTRY_CODE__")]
	pub(crate) code: String,
}

#[get("/auth-url/response")]
async fn response(session: Session, db: web::Data<reindeer::Db>, proxied_rewrite: web::Query<ProxiedRewrite>) -> Response {
	let code = &proxied_rewrite.code;

	let token = if let Ok(token) = ProxyCookieToken::from_code(&db, code).await {
		token
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let scoped_session = ScopedSessionToken::new(
		&db,
		token.user,
		token.bound_to.clone(),
		token.metadata.clone()
	).await?;
	info!("New scoped session for: {:?}", &token.metadata);
	session.insert(SCOPED_SESSION_COOKIE, scoped_session.code)?;

	Ok(HttpResponse::Ok()
		// TODO: Add realm
		.append_header((CONFIG.auth_url_email_header.as_str(), scoped_session.user.email.clone()))
		.append_header((CONFIG.auth_url_user_header.as_str(), scoped_session.user.username.unwrap_or_default()))
		.append_header((CONFIG.auth_url_name_header.as_str(), scoped_session.user.name.unwrap_or_default()))
		// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
		.finish())
}
