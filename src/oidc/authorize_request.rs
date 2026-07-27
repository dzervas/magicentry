use anyhow::Context as _;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::config::{Config, LiveConfig};
use crate::error::{AppError, OidcError};
use crate::oidc::handle_token::JWTData;
use crate::secret::MetadataKind;
use crate::service::{IdTokenSigningAlgorithm, ServiceOIDC};
use crate::user::User;

/// Implementation of <https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: String,
	pub state: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
	// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// The value is passed through unmodified from the Authentication Request to the ID Token.
	// Sufficient entropy MUST be present in the nonce values used to prevent attackers from guessing values.
	pub nonce: Option<String>,
}

impl AuthorizeRequest {
	pub async fn get_redirect_url(
		&self,
		config: &LiveConfig,
		code: &str,
		user: &User,
	) -> Option<String> {
		let redirect_url = Url::parse(&urlencoding::decode(&self.redirect_uri).ok()?).ok()?;

		// TODO: Pop this function to self, handle_authorize.rs also uses these
		let Some(service) = config.services.from_oidc_client_id(&self.client_id) else {
			tracing::warn!(
				"Invalid OIDC client_id: {} - this should NOT be possible",
				self.client_id,
			);
			return None;
		};

		let Some(ref oidc) = service.oidc else {
			tracing::warn!(
				"OIDC request was done against a non-OIDC service `{}` - this should NOT be possible",
				service.name
			);
			return None;
		};

		if !oidc.redirect_urls.contains(&redirect_url) {
			tracing::warn!(
				"Invalid OIDC redirect_uri: {} for client_id: {}",
				redirect_url,
				self.client_id
			);
			return None;
		}

		if !service.is_user_allowed(user) {
			tracing::warn!(
				"User {} is not allowed to access OIDC redirect_uri: {} for client_id: {}",
				user.email,
				redirect_url,
				self.client_id
			);
			return None;
		}

		// Use the Url type
		Some(
			redirect_url
				.clone()
				.query_pairs_mut()
				.append_pair("code", code)
				.append_pair("state", &self.state.clone().unwrap_or_default())
				.finish()
				.to_string(),
		)
	}

	pub fn generate_id_token(
		&self,
		user: &User,
		url: String,
		signing_keys: &crate::oidc::SigningKeys,
		config: &LiveConfig,
		oidc: &ServiceOIDC,
	) -> anyhow::Result<String> {
		let jwt_data = JWTData {
			client_id: self.client_id.clone(),
			user_info: user.into(),

			..JWTData::new(url, self.nonce.clone(), config)
		};
		debug!("JWT Data: {jwt_data:?}");

		let algorithm = oidc.signing_alg.into();
		let mut header = Header::new(algorithm);
		let hmac_key;
		let encoding_key = match oidc.signing_alg {
			IdTokenSigningAlgorithm::RS256 => {
				header.kid = Some(signing_keys.rsa_kid.clone());
				&signing_keys.rsa
			}
			IdTokenSigningAlgorithm::HS256 => {
				hmac_key = EncodingKey::from_secret(oidc.client_secret.as_bytes());
				&hmac_key
			}
		};
		let id_token = encode(&header, &jwt_data, encoding_key)
			.with_context(|| format!("Failed to encode ID token for user {}", user.email))?;

		Ok(id_token)
	}
}

impl MetadataKind for AuthorizeRequest {
	async fn validate(&self, _config: &Config, _db: &crate::Database) -> Result<(), AppError> {
		if let Some(code_challenge_method) = self.code_challenge_method.as_ref() {
			// TODO: Support plain
			if code_challenge_method != "S256" {
				return Err(OidcError::InvalidCodeChallengeMethod.into());
			}

			if self.code_challenge.is_none() {
				return Err(OidcError::InvalidCodeChallengeMethod.into());
			}
		}

		Ok(())
	}
}

pub mod as_string {
	use super::AuthorizeRequest;
	use serde::Deserialize as _;

	pub fn serialize<S: serde::Serializer>(
		req: &Option<AuthorizeRequest>,
		serializer: S,
	) -> Result<S::Ok, S::Error> {
		use serde::ser::Error;
		if let Some(value) = req {
			let json = serde_json::to_string(value).map_err(Error::custom)?;
			serializer.serialize_some(&json)
		} else {
			serializer.serialize_none()
		}
	}

	pub fn deserialize<'de, D: serde::Deserializer<'de>>(
		deserializer: D,
	) -> Result<Option<AuthorizeRequest>, D::Error> {
		use serde::de::Error;
		let opt_json = Option::<String>::deserialize(deserializer)?;

		opt_json.as_ref().map_or_else(
			|| Ok(None),
			|json| serde_json::from_str(json).map(Some).map_err(Error::custom),
		)
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::AuthorizeRequest;
	use crate::config::{Config, LiveConfig};
	use crate::oidc::{SigningKeys, TEST_RSA_PRIVATE_KEY_DER};
	use crate::service::{IdTokenSigningAlgorithm, ServiceOIDC};
	use crate::user::User;
	use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

	#[derive(serde::Deserialize)]
	struct Claims {
		#[allow(dead_code)]
		exp: usize,
		#[allow(dead_code)]
		aud: String,
	}

	fn signing_keys() -> SigningKeys {
		SigningKeys::from_rsa_der(TEST_RSA_PRIVATE_KEY_DER)
	}

	fn fixtures(algorithm: IdTokenSigningAlgorithm) -> (AuthorizeRequest, User, ServiceOIDC) {
		let request = AuthorizeRequest {
			scope: "openid".into(),
			response_type: "code".into(),
			client_id: "client-id".into(),
			redirect_uri: "https://client.example/callback".into(),
			state: None,
			code_challenge: None,
			code_challenge_method: None,
			nonce: Some("nonce".into()),
		};
		let user = User {
			username: "user".into(),
			realms: vec![],
			email: "user@example.com".into(),
			name: "User".into(),
		};
		let oidc = ServiceOIDC {
			client_id: "client-id".into(),
			client_secret: "a-client-secret-long-enough-for-hs256".into(),
			signing_alg: algorithm,
			redirect_urls: vec![],
		};
		(request, user, oidc)
	}

	#[test]
	fn signs_and_verifies_rs256_and_hs256_id_tokens() {
		let keys = signing_keys();
		let config = LiveConfig(Arc::new(Config::default()));

		let (request, user, oidc) = fixtures(IdTokenSigningAlgorithm::RS256);
		let token = request
			.generate_id_token(
				&user,
				"https://issuer.example".into(),
				&keys,
				&config,
				&oidc,
			)
			.unwrap();
		let header = decode_header(&token).unwrap();
		assert_eq!(header.alg, Algorithm::RS256);
		assert_eq!(header.kid.as_deref(), Some(keys.rsa_kid.as_str()));
		let jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&keys.rsa, Algorithm::RS256).unwrap();
		let mut validation = Validation::new(Algorithm::RS256);
		validation.set_audience(&["client-id"]);
		decode::<Claims>(&token, &DecodingKey::from_jwk(&jwk).unwrap(), &validation).unwrap();

		let (request, user, oidc) = fixtures(IdTokenSigningAlgorithm::HS256);
		let token = request
			.generate_id_token(
				&user,
				"https://issuer.example".into(),
				&keys,
				&config,
				&oidc,
			)
			.unwrap();
		let header = decode_header(&token).unwrap();
		assert_eq!(header.alg, Algorithm::HS256);
		assert_eq!(header.kid, None);
		let mut validation = Validation::new(Algorithm::HS256);
		validation.set_audience(&["client-id"]);
		decode::<Claims>(
			&token,
			&DecodingKey::from_secret(oidc.client_secret.as_bytes()),
			&validation,
		)
		.unwrap();
	}
}
