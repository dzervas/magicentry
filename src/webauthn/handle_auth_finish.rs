use anyhow::Context as _;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::AppState;
use crate::config::LiveConfig;
use crate::error::{AppError, AuthError};
use crate::secret::{BrowserSessionSecret, WebAuthnAuthSecret};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthFinishResponse {
	pub redirect_to: String,
}

#[axum::debug_handler]
pub async fn handle_auth_finish(
	config: LiveConfig,
	State(state): State<AppState>,
	auth: WebAuthnAuthSecret,
	jar: CookieJar,
	req: Json<PublicKeyCredential>,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
	let webauthn = state.webauthn.clone();

	let sk = webauthn
		.finish_passkey_authentication(&req, auth.metadata())
		.context("Failed to finish passkey authentication")?;

	if !sk.user_verified() {
		return Err(AuthError::InvalidTargetUser.into());
	}

	let browser_session: BrowserSessionSecret = auth.exchange(&config, &state.db).await?;

	// TODO: How to handle redirects?
	// TODO: Handle the passkey store counter

	Ok((
		jar.add(&browser_session),
		Json(AuthFinishResponse {
			redirect_to: "/".to_string(),
		}),
	))
}
