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
