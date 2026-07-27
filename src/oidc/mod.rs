use base64::Engine as _;
#[cfg(not(test))]
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey};
#[cfg(not(test))]
use rsa::RsaPrivateKey;
#[cfg(not(test))]
use rsa::pkcs1::EncodeRsaPrivateKey as _;
use sha2::{Digest as _, Sha256};

#[cfg(not(test))]
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

#[derive(Clone)]
pub struct SigningKeys {
	pub rsa: EncodingKey,
	pub rsa_kid: String,
}

#[cfg(test)]
pub(crate) const TEST_RSA_PRIVATE_KEY_DER: &[u8] =
	include_bytes!("../tests/fixtures/oidc_rsa_private.der");

impl SigningKeys {
	fn from_rsa_der(der: &[u8]) -> Self {
		let rsa = EncodingKey::from_rsa_der(der);
		let jwk = Jwk::from_encoding_key(&rsa, Algorithm::RS256)
			.expect("generated RSA key must produce a public JWK");
		let public_key = serde_json::to_vec(&jwk).expect("RSA JWK must serialize");
		let rsa_kid = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));

		Self { rsa, rsa_kid }
	}
}

#[cfg(test)]
pub async fn init(_db: &Database) -> SigningKeys {
	SigningKeys::from_rsa_der(TEST_RSA_PRIVATE_KEY_DER)
}

#[cfg(not(test))]
pub async fn init(db: &Database) -> SigningKeys {
	let der = if let Ok(Some(encoded)) = ConfigKV::get(&ConfigKeys::JWTPrivateKey, db).await {
		STANDARD
			.decode(encoded)
			.expect("Stored OIDC RSA private key is invalid base64")
	} else {
		tracing::warn!("Generating 4096-bit OIDC RSA private key, this might take a while...");
		let der = tokio::task::spawn_blocking(|| {
			let mut rng = rsa::rand_core::OsRng;
			let key = RsaPrivateKey::new(&mut rng, 4096)?;
			Ok::<_, anyhow::Error>(key.to_pkcs1_der()?.as_bytes().to_vec())
		})
		.await
		.expect("OIDC RSA key generation task failed")
		.expect("Unable to generate OIDC RSA private key");

		ConfigKV::set(&ConfigKeys::JWTPrivateKey, Some(STANDARD.encode(&der)), db)
			.await
			.expect("Unable to save OIDC RSA private key in the database");
		der
	};

	SigningKeys::from_rsa_der(&der)
}
