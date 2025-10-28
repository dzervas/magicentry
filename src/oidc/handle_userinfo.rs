use actix_web::{get, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::secret::OIDCTokenSecret;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub name: String,
	pub email: String,
	pub email_verified: bool,
	pub preferred_username: String,
}

#[get("/oidc/userinfo")]
pub async fn userinfo(oidc_token: OIDCTokenSecret) -> Response {
	let user = oidc_token.user();

	let resp = UserInfoResponse {
		user: user.email.clone(),
		name: user.name.clone(),
		email: user.email.clone(),
		email_verified: true,
		preferred_username: user.username.clone(),
	};

	Ok(HttpResponse::Ok().json(resp))
}

#[axum::debug_handler]
pub async fn handle_userinfo(
	_: axum::extract::State<crate::AppState>,
	oidc_token: OIDCTokenSecret,
) -> impl axum::response::IntoResponse {
	let user = oidc_token.user();

	let resp = UserInfoResponse {
		user: user.email.clone(),
		name: user.name.clone(),
		email: user.email.clone(),
		email_verified: true,
		preferred_username: user.username.clone(),
	};

	axum::Json(resp)
}
