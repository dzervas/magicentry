use std::borrow::Cow;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::extract::State;
use axum_extra::extract::OptionalQuery;
use tracing::warn;
use serde::{Deserialize, Serialize};

use crate::{secret::BrowserSessionSecret, AppState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
	post_logout_redirect_uri: Option<String>,
}

#[axum::debug_handler]
pub async fn handle_logout(
	State(state): State<AppState>,
	browser_session: BrowserSessionSecret,
	OptionalQuery(post_logout_redirect_uri): OptionalQuery<String>,
) -> Result<impl IntoResponse, StatusCode>  {
	browser_session.delete(&state.db).await.unwrap();

	// XXX: Open redirect
	let target_url = post_logout_redirect_uri
		.as_ref()
		.map_or_else(|| "/login".to_string(), |target| urlencoding::decode(&target.clone())
			.unwrap_or_else(|_| {
				warn!("Invalid logout redirect URL: {target}");
				Cow::from("/login")
			})
			.to_string());

	// TODO: Remove the cookie as well
	Ok(Redirect::to(&target_url))
}
