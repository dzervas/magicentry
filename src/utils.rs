use std::collections::BTreeMap;

use actix_web::http::{header, Uri};
use actix_web::HttpRequest;

use crate::error::{AppErrorKind, Result};
use crate::{CONFIG, RANDOM_STRING_LEN, TEMPLATES};

pub fn get_partial<T: serde::Serialize>(name: &str, mut data: BTreeMap<&str, String>, obj: Option<&T>) -> Result<String> {
	let config = CONFIG.try_read()?;
	let path_prefix = if config.path_prefix.ends_with('/') {
		&config.path_prefix[..config.path_prefix.len() - 1]
	} else {
		&config.path_prefix
	};

	data.insert("title", config.title.clone());
	data.insert("path_prefix", path_prefix.to_string());
	drop(config);

	let json_data = serde_json::json!({
		"data": data,
		"state": obj,
	});

	let ctx = handlebars::Context::from(json_data);
	let result = TEMPLATES.render_with_context(name, &ctx)?;

	Ok(result)
}

pub fn get_request_origin(req: &HttpRequest) -> Result<String> {
	let valid_headers = [
		header::HeaderName::from_static("x-original-url"),
		header::ORIGIN,
		header::REFERER,
		// TODO: Is this correct? oauth2 proxy handles: https://github.com/oauth2-proxy/oauth2-proxy/issues/1607#issuecomment-1086889273
		header::HOST,
	];

	for header in &valid_headers {
		if let Some(origin) = req.headers().get(header) {
			log::debug!("Origin header: {origin:?}");
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

	Err(AppErrorKind::MissingOriginHeader.into())
}

#[must_use]
pub fn random_string() -> String {
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rand::fill(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
pub mod tests {
	use crate::Database;
	

	use crate::config::ConfigFile;
	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> Database {
		// Use in-memory database for tests to avoid file system issues
		let db = crate::database::init_database("sqlite::memory:")
			.await
			.expect("Failed to initialize SQLite database");
		db
	}

	pub async fn get_valid_user() -> User {
		ConfigFile::reload()
			.await
			.expect("Failed to reload config file");
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let config = CONFIG.read().await;
		let user = config.users.iter().find(|u| u.email == user_email).unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user.to_owned()
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
