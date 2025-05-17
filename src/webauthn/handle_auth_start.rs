use actix_web::{post, web, HttpResponse};
use reindeer::Entity;
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::handle_login_post::LoginInfo;
use crate::user::User;
use crate::user_secret::WebAuthnAuthSecret;

use super::store::PasskeyStore;

#[post("/webauthn/auth/start")]
pub async fn auth_start(
	webauthn: web::Data<Webauthn>,
	form: web::Json<LoginInfo>,
	db: web::Data<crate::Database>,
) -> Response {
	// TODO: Handle the errors to avoid leaking (in)valid emails
	let passkeys = PasskeyStore::get_with_filter(|p| p.user.email == form.email, &db)?
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())?;

	let user = User::from_email(&form.email)
		.await
		.ok_or(AppErrorKind::InvalidTargetUser)?;

	let auth = WebAuthnAuthSecret::new(user, auth, &db).await?;

	Ok(HttpResponse::Ok()
		.cookie(auth.into())
		.json(resp))
}
