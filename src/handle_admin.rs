use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::*;

const ADMIN_REALM: &str = "admin";

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError};
use crate::secret::LoginLinkSecret;
use crate::secret::admin_token::{AdminApiTokenMetadata, AdminApiTokenSecret};
use crate::secret::login_link::LoginLinkRedirect;
use crate::user_store::UserStore;
use crate::{AppState, secret::BrowserSessionSecret};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
	error: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GenerateMagicLinkRequest {
	pub email: String,
	#[serde(flatten)]
	pub login_redirect: LoginLinkRedirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenerateMagicLinkResponse {
	pub token: String,
	pub link: String,
}

#[axum::debug_handler]
pub async fn handle_admin_generate_magic_link(
	_: AdminApiTokenSecret,
	State(mut state): State<AppState>,
	config: LiveConfig,
	Json(generate_magic_link_request): Json<GenerateMagicLinkRequest>,
) -> Response {
	let Some(user) = state
		.user_store
		.from_email(&generate_magic_link_request.email)
		.await
	else {
		return (
			StatusCode::BAD_REQUEST,
			Json(ErrorBody {
				error: "The target user does not exist",
			}),
		)
			.into_response();
	};

	warn!(
		"Admin request to generate a new magic link for user '{}'",
		user.email
	);

	let login_redirect = generate_magic_link_request
		.login_redirect
		.into_opt(&config)
		.await;

	let Ok(token) = LoginLinkSecret::new(user, login_redirect, &config, &state.db).await else {
		return (
			StatusCode::INTERNAL_SERVER_ERROR,
			Json(ErrorBody {
				error: "Failed to generate magic token",
			}),
		)
			.into_response();
	};
	let link = config.external_url.clone() + &token.get_login_url();

	(
		StatusCode::OK,
		Json(GenerateMagicLinkResponse {
			token: token.code().to_str_that_i_wont_print(),
			link: link,
		}),
	)
		.into_response()
}

#[axum::debug_handler]
pub async fn handle_admin_api_key_create(
	State(state): State<AppState>,
	config: LiveConfig,
	browser_session: BrowserSessionSecret,
	Json(metadata): Json<AdminApiTokenMetadata>,
) -> Result<impl IntoResponse, AppError> {
	let user = browser_session.user();
	if !user.realms.contains(&ADMIN_REALM.to_string()) {
		return Err(AuthError::NotAnAdmin.into());
	}

	warn!(
		"Generating new admin api key for '{}'",
		browser_session.user().username
	);

	let admin_api = AdminApiTokenSecret::new(user.clone(), metadata, &config, &state.db).await?;

	todo!("Show the token page");
	Ok(())
}
