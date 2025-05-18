use jwt_simple::prelude::*;
use log::debug;
use url::Url;

use crate::error::Error;
use crate::error::AppErrorKind;
use crate::oidc::handle_token::JWTData;
use crate::user::User;
use crate::user_secret::MetadataKind;
use crate::CONFIG;


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: String,
	pub state: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
}

impl AuthorizeRequest {
	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = Url::parse(&urlencoding::decode(&self.redirect_uri).ok()?).ok()?;

		let config = CONFIG.read().await;

		let Some(service) = config.services.from_oidc_redirect_url(&redirect_url) else {
			log::warn!(
				"Invalid OIDC redirect_uri: {} for client_id: {}",
				redirect_url,
				self.client_id
			);
			return None;
		};

		if !service.is_user_allowed(user) {
			log::warn!(
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

	pub async fn generate_id_token(
		&self,
		user: &User,
		url: String,
		keypair: &RS256KeyPair,
	) -> Result<String, Error> {
		let jwt_data = JWTData {
			user: user.email.clone(),
			client_id: self.client_id.clone(),
			..JWTData::new(url).await
		};
		debug!("JWT Data: {:?}", jwt_data);

		let config = CONFIG.read().await;
		let claims = Claims::with_custom_claims(
			jwt_data,
			Duration::from_millis(
				config
					.session_duration
					.num_milliseconds()
					.try_into()
					.map_err(|_| AppErrorKind::InvalidDuration)?,
			),
		);
		let id_token = keypair.sign(claims)?;

		Ok(id_token)
	}
}

impl MetadataKind for AuthorizeRequest {
	async fn validate(&self, _db: &reindeer::Db) -> crate::error::Result<()> {
		if let Some(code_challenge_method) = self.code_challenge_method.as_ref() {
			// TODO: Support plain
			if code_challenge_method != "S256" {
				return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
			}

			if self.code_challenge.is_none() {
				return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
			}
		}

		Ok(())
	}
}

pub mod as_string {
	use super::*;

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

		if let Some(json) = &opt_json {
			serde_json::from_str(&json).map(Some).map_err(Error::custom)
		} else {
			Ok(None)
		}
	}
}
