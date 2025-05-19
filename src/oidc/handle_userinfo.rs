use actix_web::{get, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::secret::OIDCTokenSecret;

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
pub async fn userinfo(oidc_token: OIDCTokenSecret) -> Response {
	let user = oidc_token.user();

	let resp = UserInfoResponse {
		user: &user.email,
		name: &user.name,
		email: &user.email,
		email_verified: true,
		preferred_username: &user.username,
	};

	Ok(HttpResponse::Ok().json(resp))
}
