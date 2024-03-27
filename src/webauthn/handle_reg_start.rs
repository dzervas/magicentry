use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web};
use webauthn_rs::prelude::*;

use crate::error::Result;
use crate::token::{SessionToken, WebauthnToken};

use super::WEBAUTHN_COOKIE;

#[post("/webauthn/register/start")]
pub async fn reg_start(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Webauthn>) -> Result<Json<CreationChallengeResponse>> {
	let token = SessionToken::from_session(&db, &session).await?;
	let reg_user = token.user.clone();

	let (ccr, reg_state) = webauthn
		.start_passkey_registration(
			(&token.user).into(),
			&token.user.email.clone(),
			&token.user.name.unwrap_or(token.user.email),
			None
		)?;

	let reg_state_str = serde_json::to_string(&reg_state)?;
	let registration = WebauthnToken::new(&db, reg_user, Some(token.code), Some(reg_state_str)).await?;
	session.insert(WEBAUTHN_COOKIE, registration.code)?;

	Ok(Json(ccr))
}
