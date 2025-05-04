use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use reindeer::{AutoIncrementEntity, Entity};
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::token::WebauthnToken;

use super::store::PasskeyStore;
use super::WEBAUTHN_COOKIE;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(
	session: Session,
	db: web::Data<reindeer::Db>,
	webauthn: web::Data<Webauthn>,
	req: Json<RegisterPublicKeyCredential>,
) -> Response {
	// Since we trust the registration token and it holds the user, we treat it as an authentication token as well
	let reg_state_code = session
		.remove_as::<String>(WEBAUTHN_COOKIE)
		.ok_or(AppErrorKind::SecretNotFound)??;
	let reg_state_token = WebauthnToken::from_code(&db, &reg_state_code).await?;
	let reg_state = serde_json::from_str(
		&reg_state_token
			.metadata
			.ok_or(AppErrorKind::SecretNotFound)?,
	)?;

	let sk = webauthn.finish_passkey_registration(&req, &reg_state)?;

	if !PasskeyStore::get_with_filter(|p| p.passkey.cred_id() == sk.cred_id(), &db)?.is_empty() {
		return Err(AppErrorKind::PasskeyAlreadyRegistered.into());
	}

	let passkey = PasskeyStore {
		id: PasskeyStore::get_next_key(&db)?,
		user: reg_state_token.user,
		passkey: sk,
	};
	passkey.save(&db)?;

	Ok(HttpResponse::Ok().finish())
}
