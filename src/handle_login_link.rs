use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use log::info;
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::handle_login_action::ScopedLogin;
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::model::{Token, TokenKind};
use crate::{AUTHORIZATION_COOKIE, SCOPED_LOGIN, SESSION_COOKIE};

#[get("/login/{magic}")]
async fn login_link(magic: web::Path<String>, session: Session, db: web::Data<SqlitePool>) -> Response {
	let user = if let Some(user) = Token::from_code(&db, &magic, TokenKind::MagicLink).await?.get_user() {
		user
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let user_session = Token::new(&db, TokenKind::Session, &user, None, None).await?;
	info!("User {} logged in", &user.email);
	let oidc_authorize_req_opt = session.remove_as::<AuthorizeRequest>(AUTHORIZATION_COOKIE);
	let scoped_login_opt = session.remove_as::<ScopedLogin>(SCOPED_LOGIN);
	session.insert(SESSION_COOKIE, user_session.code.clone())?;

	// This assumes that the cookies persist during the link-clicking dance, could embed the state in the link
	if let Some(Ok(oidc_auth_req)) = oidc_authorize_req_opt {
		// let oidc_code = Token::new(&db, TokenKind::OIDCCode, &user, Some(user_session.code), Some(String::try_from(oidc_auth_req)?)).await?.code;
		let oidc_code = oidc_auth_req.generate_session_code(&db, &user, user_session.code).await?.code;
		let redirect_url = oidc_auth_req.get_redirect_url(&oidc_code).ok_or(AppErrorKind::InvalidRedirectUri)?;
		info!("Redirecting to client {}", &oidc_auth_req.client_id);
		Ok(HttpResponse::Found()
			.append_header(("Location", redirect_url.as_str()))
			.finish())
	} else if let Some(Ok(scoped_login)) = scoped_login_opt {
		let scoped_code = Token::new(&db, TokenKind::ProxyCookie, &user, Some(user_session.code), Some(scoped_login.clone().into())).await?.code;
		let redirect_url = scoped_login.get_redirect_url(&scoped_code).ok_or(AppErrorKind::InvalidRedirectUri)?;
		info!("Redirecting to scope {}", &scoped_login.scope);
		Ok(HttpResponse::Found()
			.append_header(("Location", redirect_url.as_str()))
			.finish())
	} else {
		Ok(HttpResponse::Found()
			.append_header(("Location", "/"))
			.finish())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_link() {
		let db = &db_connect().await;
		let user = get_valid_user();
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_link)
		)
		.await;

		let token = Token::new(&db, TokenKind::MagicLink, &user, None, None).await.unwrap();

		// Assuming a valid session exists in the database
		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code).as_str())
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/");

		// Assuming an invalid session
		let req = actix_test::TestRequest::get()
			.uri("/login/invalid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
