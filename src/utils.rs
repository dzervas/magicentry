use std::borrow::Cow;
use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::{header, Uri};
use actix_web::HttpRequest;
use handlebars::RenderError;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use reindeer::Db;

use crate::handle_login_action::ScopedLogin;
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::token::{ProxyCookieToken, SessionToken};
use crate::{AUTHORIZATION_COOKIE, CONFIG, RANDOM_STRING_LEN, SCOPED_LOGIN, TEMPLATES};
use crate::error::{AppErrorKind, Result};

pub fn get_partial(name: &str, mut data: BTreeMap<&'static str, Cow<str>>) -> std::result::Result<String, RenderError> {
	let path_prefix = if CONFIG.path_prefix.ends_with('/') {
		&CONFIG.path_prefix[..CONFIG.path_prefix.len() - 1]
	} else {
		&CONFIG.path_prefix
	};

	// TODO: Serialize the whole CONFIG
	data.insert("title", CONFIG.title.clone().into());
	data.insert("path_prefix", path_prefix.into());

	TEMPLATES.render(name, &data)
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

pub async fn get_post_login_location(db: &Db, session: &Session, user_session: &SessionToken) -> Result<String> {
	let oidc_authorize_req_opt = session.remove_as::<AuthorizeRequest>(AUTHORIZATION_COOKIE);
	let scoped_login_opt = session.remove_as::<ScopedLogin>(SCOPED_LOGIN);

	if let Some(Ok(oidc_auth_req)) = oidc_authorize_req_opt {
		// let oidc_code = Token::new(&db, TokenKind::OIDCCode, &user, Some(user_session.code), Some(String::try_from(oidc_auth_req)?)).await?.code;
		let oidc_code = oidc_auth_req.generate_session_code(&db, user_session.user.clone(), user_session.code.clone()).await?.code;
		let redirect_url = oidc_auth_req.get_redirect_url(&oidc_code).ok_or(AppErrorKind::InvalidRedirectUri)?;
		log::info!("Redirecting to client {}", &oidc_auth_req.client_id);
		Ok(redirect_url)
	} else if let Some(Ok(scoped_login)) = scoped_login_opt {
		let scoped_code = ProxyCookieToken::new(&db, user_session.user.clone(), Some(user_session.code.clone()), Some(scoped_login.clone().into())).await?.code;
		let redirect_url = scoped_login.get_redirect_url(&scoped_code).ok_or(AppErrorKind::InvalidRedirectUri)?;
		log::info!("Redirecting to scope {}", &scoped_login.scope);
		Ok(redirect_url)
	} else {
		Ok("/".to_string())
	}
}

#[cfg(test)]
pub mod tests {
	use reindeer::Db;
	use reindeer::Entity;

	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> Db {
		let db = reindeer::open(&CONFIG.database_url).expect("Failed to open reindeer database.");
		crate::config::ConfigKV::register(&db).expect("Failed to register config_kv entity");
		crate::token::register_token_kind(&db).expect("Failed to register token kinds");

		db
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
