use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use sqlx::SqlitePool;
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::token::SessionToken;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(session: Session, db: web::Data<SqlitePool>, webauthn: web::Data<Webauthn>, req: Json<RegisterPublicKeyCredential>) -> Response {
	let Ok(token) = SessionToken::from_session(&db, &session).await else {
		return Err(AppErrorKind::NotLoggedIn.into());
	};
	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

	// let sk = webauthn.finish_passkey_registration(&req, &reg_state)?;

	// println!("Registration state: {:?}", reg_state);

	Ok(HttpResponse::Ok().finish())
}
