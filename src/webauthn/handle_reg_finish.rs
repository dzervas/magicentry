use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};

use webauthn_rs::prelude::*;

use crate::error::{WebAuthnError, Response};
use anyhow::Context as _;
use crate::secret::WebAuthnRegSecret;

use super::store::PasskeyStore;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(
	reg_secret: WebAuthnRegSecret,
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
	req: Json<RegisterPublicKeyCredential>,
) -> Response {
	let sk = webauthn.finish_passkey_registration(&req, reg_secret.metadata())
		.context("Failed to finish passkey registration")?;

	// Check if this passkey is already registered by getting all passkeys for this user
	// and checking if any have the same credential ID
	let existing_passkeys = PasskeyStore::get_by_user(reg_secret.user(), &db).await?;
	if existing_passkeys.iter().any(|p| p.passkey.cred_id() == sk.cred_id()) {
		return Err(WebAuthnError::AlreadyRegistered.into());
	}

	let mut passkey = PasskeyStore {
		id: None, // Will be set automatically when saving
		user: reg_secret.user().clone(),
		passkey: sk,
	};
	passkey.save(&db).await?;

	Ok(HttpResponse::Ok().finish())
}

#[axum::debug_handler]
pub async fn handle_reg_finish(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	reg_secret: WebAuthnRegSecret,
	req: axum::Json<RegisterPublicKeyCredential>,
) -> Result<impl axum::response::IntoResponse, crate::error::AppError> {
	let webauthn = state.webauthn.clone();
	let db = state.db.clone();

	let sk = webauthn.finish_passkey_registration(&req, reg_secret.metadata())
		.context("Failed to finish passkey registration")?;

	// Check if this passkey is already registered by getting all passkeys for this user
	// and checking if any have the same credential ID
	let existing_passkeys = PasskeyStore::get_by_user(reg_secret.user(), &db).await?;
	if existing_passkeys.iter().any(|p| p.passkey.cred_id() == sk.cred_id()) {
		return Err(WebAuthnError::AlreadyRegistered.into());
	}

	let mut passkey = PasskeyStore {
		id: None, // Will be set automatically when saving
		user: reg_secret.user().clone(),
		passkey: sk,
	};
	passkey.save(&db).await?;

	Ok(axum::response::Json(passkey))
}
