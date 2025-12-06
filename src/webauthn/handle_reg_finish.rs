use anyhow::Context as _;
use axum::extract::State;
use axum::response::{IntoResponse, Json};
use webauthn_rs::prelude::*;

use crate::error::{AppError, WebAuthnError};
use crate::secret::WebAuthnRegSecret;

use super::store::PasskeyStore;

#[axum::debug_handler]
pub async fn handle_reg_finish(
	State(state): State<crate::AppState>,
	reg_secret: WebAuthnRegSecret,
	req: Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, AppError> {
	let webauthn = state.webauthn.clone();

	let sk = webauthn
		.finish_passkey_registration(&req, reg_secret.metadata())
		.context("Failed to finish passkey registration")?;

	// Check if this passkey is already registered by getting all passkeys for this user
	// and checking if any have the same credential ID
	let existing_passkeys = PasskeyStore::get_by_user(reg_secret.user(), &state.db).await?;
	if existing_passkeys
		.iter()
		.any(|p| p.passkey.cred_id() == sk.cred_id())
	{
		return Err(WebAuthnError::AlreadyRegistered.into());
	}

	let mut passkey = PasskeyStore {
		id: None, // Will be set automatically when saving
		user: reg_secret.user().clone(),
		passkey: sk,
	};
	passkey.save(&state.db).await?;

	Ok(Json(passkey))
}
