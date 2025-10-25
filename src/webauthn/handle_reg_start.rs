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
