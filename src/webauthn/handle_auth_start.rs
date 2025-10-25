use actix_web::{post, web, HttpResponse};

use webauthn_rs::prelude::*;

use crate::error::{AuthError, Response};
use anyhow::Context as _;
use crate::handle_login_post::LoginInfo;
use crate::user::User;
use crate::secret::WebAuthnAuthSecret;

use super::store::PasskeyStore;

#[post("/webauthn/auth/start")]
pub async fn auth_start(
	webauthn: web::Data<Webauthn>,
	form: web::Json<LoginInfo>,
	db: web::Data<crate::Database>,
) -> Response {
	// TODO: Handle the errors to avoid leaking (in)valid emails
	let user = User::from_email(&form.email)
		.await
		.ok_or(AuthError::InvalidTargetUser)?;
	
	let passkey_stores = PasskeyStore::get_by_user(&user, &db).await?;
	let passkeys = passkey_stores
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())
		.context("Failed to start passkey authentication")?;

	let auth = WebAuthnAuthSecret::new(user, auth, &db).await?;

	Ok(HttpResponse::Ok()
		.cookie(auth.into())
		.json(resp))
}
