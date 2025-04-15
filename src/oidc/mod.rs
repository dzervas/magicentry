use jwt_simple::algorithms::RS256KeyPair;
use reindeer::{Db, Entity};

use crate::config::{ConfigKV, ConfigKeys};

pub mod client;
pub mod handle_authorize;
pub mod handle_discover;
pub mod handle_jwks;
pub mod handle_token;
pub mod handle_userinfo;

#[macro_export]
macro_rules! generate_cors_preflight {
	($func_name:ident, $path:expr, $methods:expr) => {
		#[actix_web::options($path)]
		pub async fn $func_name(req: actix_web::HttpRequest) -> impl actix_web::Responder {
			use actix_web::HttpResponse;

			let allowed_origins = crate::CONFIG.read().await.allowed_origins();
			let Some(origin_val) = req.headers().get("Origin") else {
				return HttpResponse::BadRequest().finish();
			};

			let Ok(origin) = origin_val.to_str() else {
				return HttpResponse::BadRequest().finish();
			};

			if !allowed_origins.contains(&origin.to_string()) {
				return HttpResponse::Forbidden().finish();
			}

			HttpResponse::NoContent()
				.append_header(("Access-Control-Allow-Origin", origin))
				.append_header(("Access-Control-Allow-Headers", "Content-Type"))
				.append_header((
					"Access-Control-Allow-Methods",
					concat!($methods, ", OPTIONS"),
				))
				.finish()
		}
	};
}

pub async fn init(db: &Db) -> RS256KeyPair {
	if let Ok(Some(keypair)) = ConfigKV::get(&ConfigKeys::JWTKeyPair, db) {
		let pem = keypair
			.value
			.expect("Failed to load JWT keypair from database");
		RS256KeyPair::from_pem(&pem).expect("Failed to load JWT keypair from database")
	} else {
		log::warn!("Generating JWT keypair for RSA 4096. This is going to take some time...");
		let keypair = RS256KeyPair::generate(4096).expect("Failed to generate RSA 4096 keypair");
		let keypair_pem = keypair
			.to_pem()
			.expect("Failed to convert keypair to PEM - that's super weird");

		ConfigKV::set(ConfigKeys::JWTKeyPair, Some(keypair_pem), db)
			.expect("Unable to save secret in the database");

		keypair
	}
	.with_key_id("default")
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::token::MagicLinkToken;
	use crate::utils::tests::*;

	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::Cookie;
	use actix_web::cookie::Key;
	use actix_web::http::StatusCode;
	use actix_web::test as actix_test;
	use actix_web::web;
	use actix_web::App;
	use actix_web_httpauth::extractors::basic;

	use tests::handle_token::TokenRequest;
	use tests::handle_token::TokenResponse;
	use tests::handle_userinfo::UserInfoResponse;

	#[actix_web::test]
	async fn test_oidc() {
		let db = &db_connect().await;
		let secret = Key::from(&[0; 64]);
		let user = get_valid_user().await;
		let keypair = RS256KeyPair::from_pem("-----BEGIN PRIVATE KEY-----\n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\n9gv9wAIJD+X4ojJsqb8tX9sSmIiO\n-----END PRIVATE KEY-----")
			.unwrap()
			.with_key_id("default");

		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.app_data(web::Data::new(keypair))
				.app_data(basic::Config::default().realm("MagicEntry"))
				.service(crate::handle_login_link::login_link)
				.service(handle_authorize::authorize_get)
				.service(handle_authorize::authorize_post)
				.service(handle_token::token)
				.service(handle_userinfo::userinfo)
				.wrap(SessionMiddleware::builder(CookieSessionStore::default(), secret).build()),
		)
		.await;

		let client_id = "my_client";
		let client_secret = "my_secret";
		let redirect_url = "https://openidconnect.net/callback";
		let redirect = urlencoding::encode(redirect_url);
		let state = "my_awesome_state";

		let req = actix_test::TestRequest::get()
			.uri(format!(
				"/oidc/authorize?client_id={}&redirect_uri={}&scope=openid%20profile%20email%20phone%20address&response_type=code&state={}",
				client_id,
				redirect,
				state
			).as_str())
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		assert_eq!(resp.status(), StatusCode::FOUND);

		// Unauthenticated user should be redirected to login
		let target = resp.headers().get("Location").unwrap().to_str().unwrap();
		assert!(target.starts_with("http://localhost:8080/login"));

		let token = MagicLinkToken::new(db, user, None, None).await.unwrap();

		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code).as_str())
			.cookie(parsed_cookie)
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		debug!("Headers: {:?}", resp.headers());
		assert!(resp
			.headers()
			.get("Location")
			.unwrap()
			.to_str()
			.unwrap()
			.starts_with(redirect_url));

		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		let req = actix_test::TestRequest::get()
			.uri(format!(
				"/oidc/authorize?client_id={}&redirect_uri={}&scope=openid%20profile%20email%20phone%20address&response_type=code&state={}",
				client_id,
				redirect,
				state
			).as_str())
			.cookie(parsed_cookie.clone())
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		let body = actix_test::read_body(resp).await;
		let body_str = std::str::from_utf8(&body).unwrap();
		let html_parse = scraper::Html::parse_document(body_str);
		let a_href = html_parse
			.select(&scraper::Selector::parse("a").unwrap())
			.next()
			.unwrap()
			.value()
			.attr("href")
			.unwrap();
		assert!(a_href.starts_with(redirect_url));
		let location_url = reqwest::Url::parse(a_href).unwrap();
		let code = location_url
			.query_pairs()
			.find(|(k, _)| k == "code")
			.unwrap()
			.1
			.to_string();
		debug!("New Code: {}", code);

		let req = actix_test::TestRequest::post()
			.uri("/oidc/token")
			.set_form(&TokenRequest {
				grant_type: "authorization_code".to_string(),
				code,
				client_id: Some(client_id.to_string()),
				client_secret: Some(client_secret.to_string()),
				code_verifier: None,
				redirect_uri: Some(redirect.to_string()),
			})
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		let body = actix_test::read_body(resp).await;
		debug!("Body: {:?}", body);
		let resp_token = serde_json::from_slice::<TokenResponse>(&body).unwrap();

		let req = actix_test::TestRequest::get()
			.uri("/oidc/userinfo")
			.append_header((
				"Authorization",
				format!("Bearer {}", resp_token.access_token),
			))
			.to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		let body = actix_test::read_body(resp).await;
		let resp_userinfo = serde_json::from_slice::<UserInfoResponse<'_>>(&body).unwrap();
		assert_eq!(
			resp_userinfo,
			UserInfoResponse {
				user: "valid@example.com",
				name: "Valid User",
				email: "valid@example.com",
				email_verified: true,
				preferred_username: "valid",
			}
		)
	}
}
