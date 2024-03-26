use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web};
use passkey_authenticator::Authenticator;
use passkey_types::ctap2::make_credential;

use crate::error::{AppErrorKind, Result};
use crate::token::SessionToken;

#[post("/webauthn/register/start")]
pub async fn reg_start(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Authenticator>, req: web::Json<make_credential::Request>) -> Result<Json<make_credential::Response>> {
	let Ok(token) = SessionToken::from_session(&db, &session).await else {
		return Err(AppErrorKind::NotLoggedIn.into());
	};
	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;
	// TODO: Manage the UUIDs
	let uuid = Uuid::new_v4();

	let (ccr, reg_state) = webauthn
		.start_passkey_registration(
			uuid,
			&user.username.unwrap_or(user.email.clone()),
			&user.name.unwrap_or(user.email),
			None
		)?;

	println!("Registration state: {:?}", reg_state);

	Ok(Json(ccr))
}
