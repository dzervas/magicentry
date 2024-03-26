use actix_session::Session;
use actix_web::http::header::{self, ContentType};
use actix_web::{get, web, HttpResponse};
use formatx::formatx;

use crate::error::{AppErrorKind, Response};
use crate::token::{ProxyCookieToken, SessionToken};
use crate::{CONFIG, SCOPED_LOGIN};
use crate::utils::get_partial;

#[get("/")]
async fn index(session: Session, db: web::Data<reindeer::Db>) -> Response {
	let Ok(token) = SessionToken::from_session(&db, &session).await else {
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish())
	};

	let user = token.get_user().ok_or(AppErrorKind::InvalidTargetUser)?;

	let index_page = formatx!(
		get_partial("index"),
		email = &user.email,
		path_prefix = &CONFIG.path_prefix
	)?;


	if let Some(Ok(scope)) = session.remove_as::<String>(SCOPED_LOGIN) {
		let proxy_cookie = ProxyCookieToken::new(&db, &user, Some(token.code.clone()), Some(scope.clone())).await?;
		Ok(HttpResponse::Found()
			.append_header((header::LOCATION, format!("{}?code={}", scope, proxy_cookie.code)))
			.finish())
	} else {
		Ok(HttpResponse::Ok()
			// TODO: Add realm
			.append_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
			.append_header((CONFIG.auth_url_user_header.as_str(), user.username.unwrap_or_default()))
			.append_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()))
			// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
			.content_type(ContentType::html())
			.body(index_page))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::token::MagicLinkToken;
	use crate::utils::tests::*;
	use crate::{SESSION_COOKIE, handle_login_link};

	use std::collections::HashMap;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Cookie, Key, SameSite};
	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_index() {
		let db = &db_connect().await;
		let mut session_map = HashMap::new();
		let secret = Key::from(&[0; 64]);
		let user = get_valid_user();
		session_map.insert(SESSION_COOKIE, "valid_session_id");

		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.service(handle_login_link::login_link)
				.wrap(
					SessionMiddleware::builder(
						CookieSessionStore::default(),
						secret
					)
					.cookie_secure(false)
					.cookie_same_site(SameSite::Lax)
					.build())
		)
		.await;

		let req = actix_test::TestRequest::get().uri("/").to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");

		let token = MagicLinkToken::new(&db, &user, None, None).await.unwrap();

		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code).as_str())
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/");

		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		let req = actix_test::TestRequest::get()
			.uri("/")
			.cookie(parsed_cookie)
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.headers().get(CONFIG.auth_url_user_header.as_str()).unwrap(), "valid");
		assert_eq!(resp.headers().get(CONFIG.auth_url_email_header.as_str()).unwrap(), "valid@example.com");

		let req = actix_test::TestRequest::get()
			.uri("/")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
