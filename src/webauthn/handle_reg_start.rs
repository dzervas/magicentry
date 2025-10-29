use actix_web::{post, web, HttpResponse};
use anyhow::Context as _;
use webauthn_rs::prelude::*;

use crate::config::LiveConfig;
use crate::error::Response;
use crate::secret::{BrowserSessionSecret, WebAuthnRegSecret};

#[post("/webauthn/register/start")]
pub async fn reg_start(
	config: LiveConfig,
	browser_session: BrowserSessionSecret,
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
) -> Response {
	let user = browser_session.user().clone();

	let (ccr, reg_state) = webauthn.start_passkey_registration(
		(&user).into(),
		&user.email.clone(),
		&user.name.clone(),
		None,
	)
	.context("Failed to start passkey registration")?;

	let reg = WebAuthnRegSecret::new(user, reg_state, &config, &db).await?;

	Ok(HttpResponse::Ok()
		.cookie(reg.into())
		.json(ccr))
}

#[axum::debug_handler]
pub async fn handle_reg_start(
	config: LiveConfig,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session: BrowserSessionSecret,
	jar: axum_extra::extract::CookieJar,
) -> Result<(axum_extra::extract::CookieJar, impl axum::response::IntoResponse), crate::error::AppError> {
	let user = browser_session.user().clone();

	let (ccr, reg_state) = state.webauthn.start_passkey_registration(
		(&user).into(),
		&user.email.clone(),
		&user.name.clone(),
		None,
	)
	.context("Failed to start passkey registration")?;

	let reg = WebAuthnRegSecret::new(user, reg_state, &config, &state.db).await?;

	Ok((
		jar.add(&reg),
		axum::response::Json(ccr),
	))
}
