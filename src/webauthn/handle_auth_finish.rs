use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::config::LiveConfig;
use crate::error::{Response, AuthError};
use crate::secret::{WebAuthnAuthSecret, BrowserSessionSecret};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthFinishResponse {
	pub redirect_to: String,
}

#[post("/webauthn/auth/finish")]
pub async fn auth_finish(
	config: LiveConfig,
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
	auth: WebAuthnAuthSecret,
	Json(req): Json<PublicKeyCredential>,
) -> Response {
	let sk = webauthn.finish_passkey_authentication(&req, auth.metadata())
		.context("Failed to finish passkey authentication")?;

	if !sk.user_verified() {
		return Err(AuthError::InvalidTargetUser.into());
	}

	let browser_session: BrowserSessionSecret = auth.exchange(&config, &db).await?;
	let cookie = (&browser_session).into();

	// TODO: How to handle redirects?
	// TODO: Handle the passkey store counter

	Ok(HttpResponse::Ok()
		.cookie(cookie)
		.json(AuthFinishResponse {
			redirect_to: "/".to_string(),
		}
	))
}

#[axum::debug_handler]
pub async fn handle_auth_finish(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	auth: WebAuthnAuthSecret,
	jar: axum_extra::extract::CookieJar,
	req: axum::Json<PublicKeyCredential>,
) -> Result<(axum_extra::extract::CookieJar, impl axum::response::IntoResponse), crate::error::AppError> {
	let webauthn = state.webauthn.clone();

	let sk = webauthn.finish_passkey_authentication(&req, auth.metadata())
		.context("Failed to finish passkey authentication")?;

	if !sk.user_verified() {
		return Err(AuthError::InvalidTargetUser.into());
	}

	let browser_session: BrowserSessionSecret = auth.exchange(&state.config.into(), &state.db).await?;

	// TODO: How to handle redirects?
	// TODO: Handle the passkey store counter

	Ok((
		jar.add(&browser_session),
		axum::response::Json(AuthFinishResponse {
			redirect_to: "/".to_string(),
		})
	))
}
