use actix_web::http::{header, Uri};
use actix_web::HttpRequest;

use crate::error::{AuthError};
use crate::{PROXY_ORIGIN_HEADER, RANDOM_STRING_LEN};

pub fn get_request_origin(req: &HttpRequest) -> anyhow::Result<String> {
	let valid_headers = [
		header::HeaderName::from_static(PROXY_ORIGIN_HEADER),
		header::ORIGIN,
		header::REFERER,
		// TODO: Is this correct? oauth2 proxy handles: https://github.com/oauth2-proxy/oauth2-proxy/issues/1607#issuecomment-1086889273
		header::HOST,
	];

	for header in &valid_headers {
		if let Some(origin) = req.headers().get(header) {
			tracing::debug!("Origin header: {origin:?}");
			let Ok(origin_str) = origin.to_str() else {
				continue;
			};
			let Ok(origin_uri) = origin_str.parse::<Uri>() else {
				continue;
			};
			let Some(origin_scheme) = origin_uri.scheme_str() else {
				continue;
			};
			let Some(origin_authority) = origin_uri.authority() else {
				continue;
			};

			return Ok(format!("{origin_scheme}://{origin_authority}"));
		}
	}

	Err(AuthError::MissingOriginHeader.into())
}

pub fn random_string() -> String {
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rand::fill(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
pub mod tests {
	use axum_test::TestServer;

	use crate::app_build::axum_build;
	use crate::{CONFIG, Database};
	use crate::config::Config;
	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> Database {
		// Use in-memory database for tests to avoid file system issues
		crate::database::init_database("sqlite::memory:")
			.await
			.expect("Failed to initialize SQLite database")
	}

	pub async fn get_valid_user() -> User {
		Config::reload()
			.await
			.expect("Failed to reload config file");
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = {
			let config = CONFIG.read().await;
			config.users
				.iter()
				.find(|u| u.email == user_email)
				.unwrap()
				.clone()
		};

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	pub async fn server() -> TestServer {
		let db = db_connect().await;
		let server = axum_build(db, vec![], None).await;
		TestServer::new(server).unwrap()
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
