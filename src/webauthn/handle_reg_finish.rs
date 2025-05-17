use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use reindeer::{AutoIncrementEntity, Entity};
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::user_secret::WebAuthnRegSecret;

use super::store::PasskeyStore;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(
	reg: WebAuthnRegSecret,
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
	req: Json<RegisterPublicKeyCredential>,
) -> Response {
	let sk = webauthn.finish_passkey_registration(&req, reg.metadata())?;

	if !PasskeyStore::get_with_filter(|p| p.passkey.cred_id() == sk.cred_id(), &db)?.is_empty() {
		return Err(AppErrorKind::PasskeyAlreadyRegistered.into());
	}

	let passkey = PasskeyStore {
		id: PasskeyStore::get_next_key(&db)?,
		user: reg.user().clone(),
		passkey: sk,
	};
	passkey.save(&db)?;

	Ok(HttpResponse::Ok().finish())
}
