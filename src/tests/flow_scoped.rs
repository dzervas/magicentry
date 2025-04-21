use crate::utils::tests::db_connect;
use crate::*;
use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::test::{call_service, TestRequest};

use actix_web::cookie::{Cookie, Key};
use actix_web::http::StatusCode;
use actix_web::{test as actix_test, web, App};
use actix_web_httpauth::extractors::basic;

#[actix_web::test]
async fn test_global_login() {
	let db = db_connect().await;
	let secret = Key::from(&[0; 64]);
	let email_stub: SmtpTransport = lettre::transport::stub::AsyncStubTransport::new_ok();
	let app = actix_test::init_service(
		App::new()
			.app_data(web::Data::new(db))
			.app_data(web::Data::new(Some(email_stub.clone())))
			.app_data(web::Data::new(None::<reqwest::Client>))
			.app_data(basic::Config::default().realm("MagicEntry"))
			.service(handle_index::index)
			.service(handle_login_page::login_page)
			.service(handle_login_action::login_action)
			.service(handle_login_link::login_link)
			.service(handle_logout::logout)
			.service(auth_url::handle_status::status)
			.wrap(
				SessionMiddleware::builder(CookieSessionStore::default(), secret)
					.cookie_content_security(actix_session::config::CookieContentSecurity::Signed)
					.cookie_secure(false)
					.build(),
			),
	)
	.await;

	let scope = "http%3A%2F%2Flocalhost%3A8080";
	let resp = call_service(
		&app,
		TestRequest::post()
			.uri(format!("/login?rd={}", scope).as_str())
			.set_form(&handle_login_action::LoginInfo {
				email: "valid@example.com".to_string(),
			})
			.to_request(),
	)
	.await;
	assert_eq!(resp.status(), StatusCode::OK);
	let headers = resp.headers().clone();
	let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
	let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();
	println!("CookieHeader: {:?}", &cookie_header);
	println!("Cookie: {:?}", &parsed_cookie);

	let messages = email_stub.messages().await;
	let login_message = &messages.first().unwrap().1;

	let login_link = login_message
		.split("http://localhost:8080")
		.nth(1)
		.unwrap()
		.replace("=\r\n", "");

	println!("Login link: {}", &login_link);

	let resp = call_service(
		&app,
		TestRequest::get()
			.uri(&login_link)
			.cookie(parsed_cookie)
			.to_request(),
	)
	.await;
	println!("Response: {:?}", &resp);
	assert_eq!(resp.status(), StatusCode::FOUND);
	let location_header = resp.headers().get("Location").unwrap().to_str().unwrap();
	println!("Location header: {}", &location_header);
	assert!(location_header.starts_with("http://localhost:8080/?code="));

	let one_time_code = location_header.split("=").nth(1).unwrap();

	let resp = call_service(
		&app,
		TestRequest::get()
			.uri("/auth-url/status")
			.cookie(Cookie::new(PROXIED_COOKIE, one_time_code))
			.append_header(("x-original-url", "http://localhost:8080"))
			.to_request(),
	)
	.await;
	assert_eq!(resp.status(), StatusCode::OK);
	let headers = resp.headers().clone();
	let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
	let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

	let resp = call_service(
		&app,
		TestRequest::get()
			.uri("/auth-url/status")
			.cookie(parsed_cookie)
			.append_header(("x-original-url", "http://localhost:8080"))
			.to_request(),
	)
	.await;
	assert_eq!(resp.status(), StatusCode::OK);
}
