use actix_web::{post, web, HttpResponse};
use anyhow::Context as _;
use webauthn_rs::prelude::*;

use crate::config::LiveConfig;
use crate::error::{AuthError, Response};
use crate::handle_login_post::LoginInfo;
use crate::user::User;
use crate::secret::WebAuthnAuthSecret;

use super::store::PasskeyStore;

#[post("/webauthn/auth/start")]
pub async fn auth_start(
	config: LiveConfig,
	webauthn: web::Data<Webauthn>,
	form: web::Json<LoginInfo>,
	db: web::Data<crate::Database>,
) -> Response {
	// TODO: Handle the errors to avoid leaking (in)valid emails
	let user = User::from_email(&config, &form.email)
		.ok_or(AuthError::InvalidTargetUser)?;
	
	let passkey_stores = PasskeyStore::get_by_user(&user, &db).await?;
	let passkeys = passkey_stores
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())
		.context("Failed to start passkey authentication")?;

	let auth = WebAuthnAuthSecret::new(user, auth, &config, &db).await?;

	Ok(HttpResponse::Ok()
		.cookie(auth.into())
		.json(resp))
}

#[axum::debug_handler]
pub async fn handle_auth_start(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	jar: axum_extra::extract::CookieJar,
	form: axum::Json<LoginInfo>,
) -> Result<(axum_extra::extract::CookieJar, impl axum::response::IntoResponse), crate::error::AppError> {
	let webauthn = state.webauthn.clone();

	// TODO: Handle the errors to avoid leaking (in)valid emails
	let user = User::from_email(&state.config.clone().into(), &form.email)
		.ok_or(AuthError::InvalidTargetUser)?;
	
	let passkey_stores = PasskeyStore::get_by_user(&user, &state.db).await?;
	let passkeys = passkey_stores
		.iter()
		.map(|p| p.passkey.clone())
		.collect::<Vec<_>>();
	let (resp, auth) = webauthn.start_passkey_authentication(passkeys.as_slice())
		.context("Failed to start passkey authentication")?;

	let auth = WebAuthnAuthSecret::new(user, auth, &state.config.into(), &state.db).await?;

	Ok((
		jar.add(&auth),
		axum::response::Json(resp),
	))
}
