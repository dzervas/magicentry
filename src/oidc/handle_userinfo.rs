use axum::{extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{secret::OIDCTokenSecret, AppState};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub name: String,
	pub email: String,
	pub email_verified: bool,
	pub preferred_username: String,
}

#[axum::debug_handler]
pub async fn handle_userinfo(
	_: State<AppState>,
	oidc_token: OIDCTokenSecret,
) -> impl IntoResponse {
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
