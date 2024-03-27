use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use webauthn_rs::prelude::*;

use crate::error::Response;
use crate::token::SessionToken;

#[post("/webauthn/register/finish")]
pub async fn reg_finish(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Webauthn>, req: Json<RegisterPublicKeyCredential>) -> Response {
	let token = SessionToken::from_session(&db, &session).await?;

	// let sk = webauthn.finish_passkey_registration(&req, &reg_state)?;

	// println!("Registration state: {:?}", reg_state);

	Ok(HttpResponse::Ok().finish())
}
