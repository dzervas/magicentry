use axum::{extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{AppState, secret::OIDCTokenSecret, user::User};

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub name: String,
	#[serde(rename = "firstName")]
	pub first_name: String,
	#[serde(rename = "lastName")]
	pub last_name: Option<String>,
	pub email: String,
	pub email_verified: bool,
	pub preferred_username: String,
	pub groups: Vec<String>,
}

impl From<&User> for UserInfoResponse {
	fn from(user: &User) -> Self {
		let name_parts = user.name.split_once(' ');

		Self {
			user: user.email.clone(),
			name: user.name.clone(),
			first_name: name_parts
				.and_then(|n| Some(n.0.to_string()))
				.unwrap_or(user.name.clone()),
			last_name: name_parts.and_then(|n| Some(n.1.to_string())),
			email: user.email.clone(),
			email_verified: true,
			preferred_username: user.username.clone(),
			groups: user.realms.clone(),
		}
	}
}

#[axum::debug_handler]
pub async fn handle_userinfo(_: State<AppState>, oidc_token: OIDCTokenSecret) -> impl IntoResponse {
	let user = oidc_token.user();
	let resp: UserInfoResponse = user.into();

	axum::Json(resp)
}
