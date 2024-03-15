use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use formatx::formatx;
use sqlx::SqlitePool;

use crate::error::Response;
use crate::user::User;
use crate::{CONFIG, LOGIN_PAGE_HTML};

#[get("/login")]
async fn login_page(session: Session, db: web::Data<SqlitePool>) -> Response {
	if User::from_session(&db, session).await?.is_some() {
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/"))
			.finish())
	}

	// TODO: Add realm
	let login_page = formatx!(
		LOGIN_PAGE_HTML.as_str(),
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
	use crate::tests::*;

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
