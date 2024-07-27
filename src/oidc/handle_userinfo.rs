use actix_web::{get, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Response, Result};
use crate::token::OIDCBearerToken;
use crate::user::User;

pub async fn token_from_request(db: &reindeer::Db, req: HttpRequest) -> Result<User> {
	let Some(auth_header) = req.headers().get("Authorization") else {
		return Err(AppErrorKind::MissingAuthorizationHeader.into());
	};

	let Ok(auth_header_str) = auth_header.to_str() else {
		return Err(AppErrorKind::InvalidAuthorizationHeader.into());
	};

	let auth_header_parts = auth_header_str.split_whitespace().collect::<Vec<&str>>();

	if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
		return Err(AppErrorKind::InvalidAuthorizationHeader.into());
	}

	let Some(auth) = auth_header_parts.get(1) else {
		return Err(AppErrorKind::InvalidAuthorizationHeader.into());
	};

	Ok(OIDCBearerToken::from_code(db, &auth.to_string())
		.await?
		.user)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse<'a> {
	#[serde(rename = "sub")]
	pub user: &'a str,
	pub name: &'a str,
	pub email: &'a str,
	pub email_verified: bool,
	pub preferred_username: &'a str,
}

#[get("/oidc/userinfo")]
pub async fn userinfo(db: web::Data<reindeer::Db>, req: HttpRequest) -> Response {
	let user = token_from_request(&db, req).await?;

	let resp = UserInfoResponse {
		user: &user.email,
		name: &user.name,
		email: &user.email,
		email_verified: true,
		preferred_username: &user.username,
	};

	Ok(HttpResponse::Ok().json(resp))
}
