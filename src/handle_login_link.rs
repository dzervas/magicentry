use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use log::info;
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::user::{UserLink, UserSession};
use crate::{AUTHORIZATION_COOKIE, SESSION_COOKIE};

#[get("/login/{magic}")]
async fn login_link(magic: web::Path<String>, session: Session, db: web::Data<SqlitePool>) -> Response {
	let user = if let Some(user) = UserLink::visit(&db, magic.clone()).await? {
		user
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let user_session = UserSession::new(&db, &user).await?;
	info!("User {} logged in", &user.email);
	session.insert(SESSION_COOKIE, user_session.session_id)?;

	// This assumes that the cookies persist during the link-clicking dance, could embed the state in the link
	if let Some(Ok(oidc_authorize)) = session.remove_as::<AuthorizeRequest>(AUTHORIZATION_COOKIE) {
		println!("Session Authorize Request: {:?}", oidc_authorize);
		let oidc_session = oidc_authorize.generate_session_code(&db, user.email.as_str()).await?;
		let redirect_url = oidc_session.get_redirect_url().ok_or(AppErrorKind::InvalidRedirectUri)?;
		info!("Redirecting to client {}", &oidc_session.request.client_id);
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
	use crate::tests::*;

	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};
	use chrono::Utc;
	use sqlx::query;

	#[actix_web::test]
	async fn test_login_magic_action() {
		let db = &db_connect().await;
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_link)
		)
		.await;

		let expiry = Utc::now().naive_utc() + chrono::Duration::try_days(1).unwrap();
		query!("INSERT INTO links (magic, email, expires_at) VALUES (?, ?, ?) ON CONFLICT(magic) DO UPDATE SET expires_at = ?",
				"valid_magic_link",
				"valid@example.com",
				expiry,
				expiry,
			)
			.execute(db)
			.await
			.unwrap();

		// Assuming a valid session exists in the database
		let req = actix_test::TestRequest::get()
			.uri("/login/valid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);

		// Assuming an invalid session
		let req = actix_test::TestRequest::get()
			.uri("/login/invalid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
	}
}
