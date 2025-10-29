use anyhow::Context as _;
use axum::extract::State;
use axum::response::{IntoResponse, Json};
use axum_extra::extract::CookieJar;

use crate::config::LiveConfig;
use crate::error::AppError;
use crate::secret::{BrowserSessionSecret, WebAuthnRegSecret};
use crate::AppState;

#[axum::debug_handler]
pub async fn handle_reg_start(
	config: LiveConfig,
	State(state): State<AppState>,
	browser_session: BrowserSessionSecret,
	jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
	let user = browser_session.user().clone();

	let (ccr, reg_state) = state.webauthn.start_passkey_registration(
		(&user).into(),
		&user.email.clone(),
		&user.name.clone(),
		None,
	)
	.context("Failed to start passkey registration")?;

	let reg = WebAuthnRegSecret::new(user, reg_state, &config, &state.db).await?;

	Ok((
		jar.add(&reg),
		Json(ccr),
	))
}
