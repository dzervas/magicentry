use actix_session::Session;
use actix_web::http::header;
use actix_web::{get, web, HttpResponse};
use log::info;

use crate::error::Response;
use crate::user_secret::LoginLinkSecret;
use crate::SESSION_COOKIE;

#[get("/login/{magic}")]
async fn login_link(
	login_secret: LoginLinkSecret,
	session: Session,
	db: web::Data<reindeer::Db>,
) -> Response {
	info!("User {} logged in", &login_secret.user().email);

	// TODO: Handle the redirect URL
	// let redirect_url = get_post_login_location(&db, &session, &user_session).await?;
	// let redirect_url = login_secret.metadata().unwrap_or_else(url::Url::from_directory_path("/"));
	let user_session = login_secret.exchange(&db).await?;
	session.insert(SESSION_COOKIE, user_session)?;

	Ok(HttpResponse::Found()
		.append_header((header::LOCATION, "/"))
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

		let token = LoginLinkSecret::new(user, None, db).await.unwrap();

		// Assuming a valid session exists in the database
		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code().to_str_that_i_wont_print()).as_str())
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

		// Re-test the used valid link
		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code().to_str_that_i_wont_print()).as_str())
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
