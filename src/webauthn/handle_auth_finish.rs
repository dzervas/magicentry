use actix_session::Session;
use actix_web::http::header;
use actix_web::web::Json;
use actix_web::{post, web, HttpResponse};
use webauthn_rs::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::token::{SessionToken, WebauthnToken};
use crate::utils::get_post_login_location;
use crate::SESSION_COOKIE;

use super::WEBAUTHN_COOKIE;

#[post("/webauthn/auth/finish")]
pub async fn auth_finish(session: Session, db: web::Data<reindeer::Db>, webauthn: web::Data<Webauthn>, req: Json<PublicKeyCredential>) -> Response {
	// Since we trust the registration token and it holds the user, we treat it as an authentication token as well
	let auth_code = session.remove_as::<String>(WEBAUTHN_COOKIE).ok_or(AppErrorKind::TokenNotFound)??;
	let auth_token = WebauthnToken::from_code(&db, &auth_code).await?;
	let auth = serde_json::from_str(&auth_token.metadata.ok_or(AppErrorKind::TokenNotFound)?)?;
	println!("{:?}", auth);

	let sk = webauthn.finish_passkey_authentication(&req, &auth)?;

	if !sk.user_verified() {
		return Err(AppErrorKind::InvalidTargetUser.into());
	}

	let user_session = SessionToken::new(&db, auth_token.user.clone(), None, None).await?;
	let redirect_url = get_post_login_location(&db, &session, &user_session).await?;
	session.insert(SESSION_COOKIE, user_session.code.clone())?;

	Ok(HttpResponse::Found()
		.append_header((header::LOCATION, redirect_url))
		.finish())
}
