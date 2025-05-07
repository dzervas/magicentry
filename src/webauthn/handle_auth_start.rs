use actix_web::web::Json;
use actix_web::{post, web};
use reindeer::Entity;
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Result};
use crate::handle_login_action::LoginInfo;
use crate::user::User;
use crate::user_secret::WebAuthnAuthSecret;

use super::store::PasskeyStore;

#[post("/webauthn/auth/start")]
pub async fn auth_start(
	webauthn: web::Data<Webauthn>,
	form: web::Json<LoginInfo>,
	db: web::Data<reindeer::Db>,
) -> Result<Json<RequestChallengeResponse>> {
	// TODO: Handle the errors to avoid leaking (in)valid emails
	let passkeys = PasskeyStore::get_with_filter(|p| p.user.email == form.email, &db)?
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())?;

	let user = User::from_config(&form.email)
		.await
		.ok_or(AppErrorKind::InvalidTargetUser)?;

	// Just store the auth secret, we don't want to give it to the user
	let _ = WebAuthnAuthSecret::new(user, auth, &db).await?;

	Ok(Json(resp))
}
