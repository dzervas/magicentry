use actix_web::{get, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::error::{Response, Result};
use crate::token::OIDCBearerToken;
use crate::user::User;

pub async fn token_from_request(db: &reindeer::Db, req: HttpRequest) -> Result<Option<User>> {
	let auth_header = if let Some(header) = req.headers().get("Authorization") {
		header
	} else {
		return Ok(None)
	};

	let auth_header_str = if let Ok(header_str) = auth_header.to_str() {
		header_str
	} else {
		return Ok(None)
	};

	let auth_header_parts = auth_header_str.split_whitespace().collect::<Vec<&str>>();

	if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
		return Ok(None)
	}

	let auth = if let Some(auth) = auth_header_parts.get(1) {
		auth
	} else {
		return Ok(None)
	};

	Ok(OIDCBearerToken::from_code(db, &auth.to_string()).await?.get_user())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub email: String,
	pub preferred_username: String,
}

#[get("/oidc/userinfo")]
pub async fn userinfo(db: web::Data<reindeer::Db>, req: HttpRequest) -> Response {
	if let Ok(Some(user)) = token_from_request(&db, req).await {
		let username = user.username.unwrap_or(user.email.clone());

		let resp = UserInfoResponse {
			user: user.email.clone(),
			email: user.email.clone(),
			preferred_username: username,
		};

		Ok(HttpResponse::Ok().json(resp))
	} else {
		Ok(HttpResponse::Unauthorized().finish())
	}
}
