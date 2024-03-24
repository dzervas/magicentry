use std::fs;

use actix_web::http::{header, Uri};
use actix_web::HttpRequest;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::{CONFIG, RANDOM_STRING_LEN};
use crate::error::{AppErrorKind, Result};

pub fn get_partial(name: &str) -> String {
	let path_prefix = if CONFIG.path_prefix.ends_with('/') {
		&CONFIG.path_prefix[..CONFIG.path_prefix.len() - 1]
	} else {
		&CONFIG.path_prefix
	};

	let outer_content = fs::read_to_string("static/outer.html").expect("Unable to open static/outer.html");
	let inner_content = fs::read_to_string(format!("static/{}.html", name)).expect(format!("Unable to open static/{}.html", name).as_str());

	formatx::formatx!(
		outer_content,
		title = &CONFIG.title,
		path_prefix = path_prefix,
		content = inner_content
	).expect(format!("Unable to format static/outer.html with title `{:?}` and path_prefix `{:?}`", &CONFIG.title, path_prefix).as_str())
}

pub fn get_request_origin(req: &HttpRequest) -> Result<String> {
	let valid_headers = [
		header::HeaderName::from_static("x-original-url"),
		header::ORIGIN,
		header::REFERER,
		// TODO: Is this correct? oauth2 proxy handles: https://github.com/oauth2-proxy/oauth2-proxy/issues/1607#issuecomment-1086889273
		header::HOST,
	];

	for header in valid_headers.iter() {
		if let Some(origin) = req.headers().get(header) {
			log::debug!("Origin header: {:?}", origin);
			let Ok(origin_str) = origin.to_str() else { continue; };
			let Ok(origin_uri) = origin_str.parse::<Uri>() else { continue; };
			let Some(origin_scheme) = origin_uri.scheme_str() else { continue; };
			let Some(origin_authority) = origin_uri.authority() else { continue; };

			return Ok(format!("{}://{}", origin_scheme, origin_authority));
		}
	}

	Err(AppErrorKind::MissingOriginHeader.into())
}

pub fn random_string() -> String {
	let mut rng = StdRng::from_entropy();
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rng.fill_bytes(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
pub mod tests {
	use sqlx::SqlitePool;

	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> SqlitePool {
		SqlitePool::connect(&CONFIG.database_url).await.expect("Failed to create pool.")
	}

	pub fn get_valid_user() -> User {
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == user_email { Some(u.clone()) } else { None })
			.unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
