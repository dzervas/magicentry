use log::warn;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::model::OIDCCodeToken;
use crate::CONFIG;
use crate::error::Result;

use super::handle_authorize::AuthorizeRequest;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OIDCClient {
	pub id: String,
	pub secret: String,
	pub redirect_uris: Vec<String>,
	pub realms: Vec<String>,
}

impl OIDCClient {
	pub async fn from_code(db: &SqlitePool, code: &str) -> Result<Option<OIDCClient>> {
		let token = OIDCCodeToken::from_code(db, code).await?;
		let auth_req = if let Some(metadata) = token.metadata {
			serde_qs::from_str::<AuthorizeRequest>(&metadata)?
		} else {
			return Ok(None)
		};

		let config_client = CONFIG.oidc_clients
			.iter()
			.find(|c|
				c.id == auth_req.client_id);

		if let Some(client) = config_client {
			if let Some(redirect_url_enc) = &auth_req.redirect_uri {
				let redirect_uri = urlencoding::decode(&redirect_url_enc)?;
				if !client.redirect_uris.contains(&redirect_uri.to_string()) {
					warn!("Invalid redirect_uri: {} for client_id: {}", redirect_uri, auth_req.client_id);
					return Ok(None);
				}
			}
		}

		Ok(config_client.cloned())
	}
}
