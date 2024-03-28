use actix_session::Session;
use actix_web::web::Json;
use actix_web::{post, web};
use reindeer::Entity;
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Result};
use crate::handle_login_action::LoginInfo;
use crate::token::WebauthnToken;
use crate::user::User;

use super::store::PasskeyStore;
use super::WEBAUTHN_COOKIE;

#[post("/webauthn/auth/start")]
pub async fn auth_start(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Webauthn>, form: web::Json<LoginInfo>) -> Result<Json<RequestChallengeResponse>> {
	// TODO: Handle the errors to avoid leaking (in)valid emails
	let passkeys = PasskeyStore::get_with_filter(|p| p.user.email == form.email, &db)?
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())?;

	let auth_str = serde_json::to_string(&auth)?;
	let user = User::from_config(&form.email).await.ok_or(AppErrorKind::InvalidTargetUser)?;
	let auth_token = WebauthnToken::new(&db, user, None, Some(auth_str)).await?;
	session.insert(WEBAUTHN_COOKIE, auth_token.code)?;

	Ok(Json(resp))
}
