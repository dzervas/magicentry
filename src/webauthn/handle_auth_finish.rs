use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::secret::WebAuthnAuthSecret;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthFinishResponse {
	pub redirect_to: String,
}

#[post("/webauthn/auth/finish")]
pub async fn auth_finish(
	db: web::Data<crate::Database>,
	webauthn: web::Data<Webauthn>,
	auth: WebAuthnAuthSecret,
	Json(req): Json<PublicKeyCredential>,
) -> Response {
	let sk = webauthn.finish_passkey_authentication(&req, auth.metadata())?;

	if !sk.user_verified() {
		return Err(AppErrorKind::InvalidTargetUser.into());
	}

	let browser_session = auth.exchange(&db).await?;
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
