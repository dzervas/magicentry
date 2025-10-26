use anyhow::Context as _;
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Deserialize, Serialize};
use tracing::debug;
use url::Url;

use crate::config::LiveConfig;
use crate::error::OidcError;
use crate::oidc::handle_token::JWTData;
use crate::user::User;
use crate::secret::MetadataKind;
use crate::CONFIG;


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
	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = Url::parse(&urlencoding::decode(&self.redirect_uri).ok()?).ok()?;

		let config = CONFIG.read().await;

		let Some(service) = config.services.from_oidc_redirect_url(&redirect_url) else {
			tracing::warn!(
				"Invalid OIDC redirect_uri: {} for client_id: {}",
				redirect_url,
				self.client_id
			);
			return None;
		};
		drop(config);

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
			redirect_url.clone()
				.query_pairs_mut()
				.append_pair("code", code)
				.append_pair("state", &self.state.clone().unwrap_or_default())
				.finish()
				.to_string()
		)
	}

	pub fn generate_id_token(
		&self,
		user: &User,
		url: String,
		encoding_key: &EncodingKey,
		config: &LiveConfig,
	) -> anyhow::Result<String> {
		let jwt_data = JWTData {
			user: user.email.clone(),
			client_id: self.client_id.clone(),

			name: user.name.clone(),
			nickname: user.username.clone(),
			email: user.email.clone(),
			email_verified: true,
			preferred_username: user.username.clone(),

			..JWTData::new(url, self.nonce.clone(), config)
		};
		debug!("JWT Data: {jwt_data:?}");

		let header = Header::default();
		let id_token = encode(&header, &jwt_data, encoding_key)
			.with_context(|| format!("Failed to encode ID token for user {}", user.email))?;

		Ok(id_token)
	}
}

impl MetadataKind for AuthorizeRequest {
	async fn validate(&self, _db: &crate::Database) -> anyhow::Result<()> {
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
			|json| serde_json::from_str(json).map(Some).map_err(Error::custom)
		)
	}
}
