use jsonwebtoken::EncodingKey;

use crate::config::{ConfigKV, ConfigKeys};
use crate::database::Database;

pub mod authorize_request;

pub mod handle_authorize;
pub mod handle_discover;
pub mod handle_jwks;
pub mod handle_token;
pub mod handle_userinfo;

pub use authorize_request::AuthorizeRequest;

#[macro_export]
macro_rules! generate_cors_preflight {
	($func_name:ident, $path:expr, $methods:expr) => {
		#[actix_web::options($path)]
		pub async fn $func_name() -> impl actix_web::Responder {
			use actix_web::HttpResponse;

			HttpResponse::NoContent()
				.append_header(("Access-Control-Allow-Origin", "*"))
				.append_header(("Access-Control-Allow-Headers", "Content-Type"))
				.append_header((
					"Access-Control-Allow-Methods",
					concat!($methods, ", OPTIONS"),
				))
				.finish()
		}
	};
}

pub async fn init(db: &Database) -> EncodingKey {
	if let Ok(Some(secret)) = ConfigKV::get(&ConfigKeys::JWTSecret, db).await {
		EncodingKey::from_secret(secret.as_bytes())
	} else {
		tracing::warn!("Generating 64-byte JWT secret");
		let mut buffer = [0u8; 64];
		rand::fill(&mut buffer);
		let secret = hex::encode(buffer);

		ConfigKV::set(ConfigKeys::JWTSecret, Some(secret.clone()), db).await
			.expect("Unable to save secret in the database");

		EncodingKey::from_secret(secret.as_bytes())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::secret::login_link::LoginLinkRedirect;
use crate::secret::LoginLinkSecret;
	use crate::utils::tests::*;

	use actix_web::cookie::Cookie;
	use actix_web::http::StatusCode;
	use actix_web::test as actix_test;
	use actix_web::web;
	use actix_web::App;
	use actix_web_httpauth::extractors::basic;
	use jsonwebtoken::EncodingKey;

	use tests::handle_token::TokenRequest;
	use tests::handle_token::TokenResponse;
	use tests::handle_userinfo::UserInfoResponse;

	#[actix_web::test]
	async fn test_oidc() {
		let config = crate::CONFIG.read().await.clone().into();
		let db = &db_connect().await;
		let user = get_valid_user().await;
		let jwt_secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
		let encoding_key = EncodingKey::from_secret(jwt_secret.as_ref());

		let app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.app_data(web::Data::new(encoding_key))
				.app_data(basic::Config::default().realm("MagicEntry"))
				.service(crate::handle_magic_link::magic_link)
				.service(handle_authorize::authorize_get)
				.service(handle_authorize::authorize_post)
				.service(handle_token::token)
				.service(handle_userinfo::userinfo)
		)
		.await;

		let client_id = "my_client";
		let client_secret = "my_secret";
		let redirect_url = "https://openidconnect.net/callback";
		let redirect = urlencoding::encode(redirect_url);
		let state = "my_awesome_state";

		let req = actix_test::TestRequest::get()
			.uri(format!("/oidc/authorize?client_id={client_id}&redirect_uri={redirect}&scope=openid%20profile%20email%20phone%20address&response_type=code&state={state}").as_str())
			.to_request();

		let resp = actix_test::call_service(&app, req).await;

		assert_eq!(resp.status(), StatusCode::FOUND);

		// Unauthenticated user should be redirected to login
		let target = resp.headers().get("Location").unwrap().to_str().unwrap();
		assert!(target.starts_with("http://localhost:8080/login"));

		let login_redirect = LoginLinkRedirect {
			rd: None,
			saml: None,
			oidc: Some(AuthorizeRequest {
				client_id: client_id.to_string(),
				redirect_uri: redirect_url.to_string(),
				scope: "openid profile email phone address".to_string(),
				response_type: "code".to_string(),
				state: Some(state.to_string()),
				code_challenge: None,
				code_challenge_method: None,
				nonce: None,
			}),
		};
		let token = LoginLinkSecret::new(user, Some(login_redirect), &config, db).await.unwrap();

		let req = actix_test::TestRequest::get()
			.uri(&token.get_login_url())
			.to_request();
		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		println!("Headers: {:?}", resp.headers());
		let location = resp.headers().get("Location").unwrap().to_str().unwrap();
		assert!(location.starts_with("/oidc/authorize"));

		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		let req = actix_test::TestRequest::get()
			.uri(location)
			.cookie(parsed_cookie.clone())
			.to_request();
		let resp = actix_test::call_service(&app, req).await;
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
		println!("New Code: {code}");

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
			.insert_header(("Origin", "https://openidconnect.net"))
			.to_request();
		let resp = actix_test::call_service(&app, req).await;
		let resp_status = resp.status();
		let body = actix_test::read_body(resp).await;
		println!("Body: {body:?}");
		assert_eq!(resp_status, StatusCode::OK);
		let resp_token = serde_json::from_slice::<TokenResponse>(&body).unwrap();

		let req = actix_test::TestRequest::get()
			.uri("/oidc/userinfo")
			.append_header((
				"Authorization",
				format!("Bearer {}", resp_token.access_token),
			))
			.to_request();
		let resp = actix_test::call_service(&app, req).await;
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
		);
	}
}
