use anyhow::Context as _;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;

use crate::config::LiveConfig;
use crate::error::{AppError, WebAuthnError};
use crate::handle_login_post::LoginInfo;
use crate::user::User;
use crate::secret::WebAuthnAuthSecret;
use crate::AppState;

use super::store::PasskeyStore;

#[axum::debug_handler]
pub async fn handle_auth_start(
	config: LiveConfig,
	State(state): State<AppState>,
	jar: CookieJar,
	form: Json<LoginInfo>,
) -> Result<(CookieJar, impl IntoResponse), AppError> {
	let webauthn = state.webauthn.clone();

	// TODO: Handle the errors to avoid leaking (in)valid emails
	let user = User::from_email(&config, &form.email)
		.ok_or(WebAuthnError::SecretNotFound)?;

	let passkey_stores = PasskeyStore::get_by_user(&user, &state.db).await?;
	let passkeys = passkey_stores
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())
		.context("Failed to start passkey authentication")?;

	let auth = WebAuthnAuthSecret::new(user, auth, &config, &state.db).await?;

	Ok((
		jar.add(&auth),
		Json(resp),
	))
}
