use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};

use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::secret::WebAuthnRegSecret;

use super::store::PasskeyStore;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(
	reg_secret: WebAuthnRegSecret,
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
	req: Json<RegisterPublicKeyCredential>,
) -> Response {
	let sk = webauthn.finish_passkey_registration(&req, reg_secret.metadata())?;

	// Check if this passkey is already registered by getting all passkeys for this user
	// and checking if any have the same credential ID
	let existing_passkeys = PasskeyStore::get_by_user(reg_secret.user(), &db).await?;
	if existing_passkeys.iter().any(|p| p.passkey.cred_id() == sk.cred_id()) {
		return Err(AppErrorKind::PasskeyAlreadyRegistered.into());
	}

	let mut passkey = PasskeyStore {
		id: None, // Will be set automatically when saving
		user: reg_secret.user().clone(),
		passkey: sk,
	};
	passkey.save(&db).await?;

	Ok(HttpResponse::Ok().finish())
}
