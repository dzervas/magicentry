use actix_web::{get, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::Response;

use super::model::OIDCAuth;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub email: String,
	pub preferred_username: String,
}

#[get("/oidc/userinfo")]
pub async fn userinfo(db: web::Data<SqlitePool>, req: HttpRequest) -> Response {
	if let Ok(Some(user)) = OIDCAuth::from_request(&db, req).await {
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
