use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web};
use webauthn_rs::prelude::*;

use crate::error::Result;
use crate::token::SessionToken;

#[post("/webauthn/register/start")]
pub async fn reg_start(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Webauthn>) -> Result<Json<CreationChallengeResponse>> {
	let token = SessionToken::from_session(&db, &session).await?;

	let (ccr, reg_state) = webauthn
		.start_passkey_registration(
			(&token.user).into(),
			&token.user.username.unwrap_or(token.user.email.clone()),
			&token.user.name.unwrap_or(token.user.email),
			None
		)?;

	println!("Registration state: {:?}", &reg_state);
	// We trust the session as it's a signed & encrypted cookie
	// session.insert("webauthn_reg_state", reg_state)?;

	Ok(Json(ccr))
}
