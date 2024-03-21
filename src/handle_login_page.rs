use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpRequest, HttpResponse};
use formatx::formatx;
use log::info;
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::handle_login_action::ScopedLogin;
use crate::model::{Token, TokenKind};
use crate::CONFIG;
use crate::utils::get_partial;

#[get("/login")]
async fn login_page(req: HttpRequest, session: Session, db: web::Data<SqlitePool>) -> Response {
	if let Ok(user_session) = Token::from_session(&db, &session).await {
		let user = user_session.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

		if let Ok(scoped_login) = serde_qs::from_str::<ScopedLogin>(req.query_string()) {
			let scoped_code = Token::new(&db, TokenKind::ProxyCookie, &user, Some(user_session.code), Some(scoped_login.clone().into())).await?.code;
			let redirect_url = scoped_login.get_redirect_url(&scoped_code).ok_or(AppErrorKind::InvalidRedirectUri)?;
			info!("Redirecting pre-authenticated user to scope {}", &scoped_login.scope);
			return Ok(HttpResponse::Found()
				.append_header(("Location", redirect_url.as_str()))
				.finish())
		}

		return Ok(HttpResponse::Found()
			.append_header(("Location", "/"))
			.finish())
	}

	// TODO: Add realm
	let login_page = formatx!(
		get_partial("login"),
		title = &CONFIG.title,
		realm = "default",
		path_prefix = &CONFIG.path_prefix
	)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_page))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Key, SameSite};
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_page() {
		let db = &db_connect().await;
		let secret = Key::from(&[0; 64]);
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_page)
				.wrap(
					SessionMiddleware::builder(
						CookieSessionStore::default(),
						secret
					)
					.cookie_secure(false)
					.cookie_same_site(SameSite::Strict)
					.build())
		)
		.await;

		let req = actix_test::TestRequest::get()
			.uri("/login")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.headers().get("Content-Type").unwrap().to_str().unwrap(), ContentType::html().to_string().as_str());
	}
}
