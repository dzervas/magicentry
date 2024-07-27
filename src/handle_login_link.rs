use actix_session::Session;
use actix_web::http::header;
use actix_web::{get, web, HttpResponse};
use log::info;

use crate::error::Response;
use crate::token::{MagicLinkToken, SessionToken};
use crate::utils::get_post_login_location;
use crate::SESSION_COOKIE;

#[get("/login/{magic}")]
async fn login_link(
	magic: web::Path<String>,
	session: Session,
	db: web::Data<reindeer::Db>,
) -> Response {
	let token = MagicLinkToken::from_code(&db, &magic).await?;

	info!("User {} logged in", &token.user.email);
	let user_session = SessionToken::new(&db, token.user.clone(), None, None).await?;
	let redirect_url = get_post_login_location(&db, &session, &user_session).await?;
	session.insert(SESSION_COOKIE, user_session.code.clone())?;

	Ok(HttpResponse::Found()
		.append_header((header::LOCATION, redirect_url))
		.finish())
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
		let user = get_valid_user().await;
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_link),
		)
		.await;

		let token = MagicLinkToken::new(&db, user, None, None).await.unwrap();

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
