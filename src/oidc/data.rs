use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;

use crate::CONFIG;
use crate::user::Result;

use super::model::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Discovery {
	pub issuer: String,
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub userinfo_endpoint: String,
	pub jwks_uri: String,

	pub scopes_supported: Vec<String>,
	pub response_types_supported: Vec<String>,
	pub subject_types_supported: Vec<String>,
	pub id_token_signing_alg_values_supported: Vec<String>,
	pub userinfo_signing_alg_values_supported: Vec<String>,
	// pub token_endpoint_auth_methods_supported: Vec<String>,
	pub claims_supported: Vec<String>,
}

impl Discovery {
	pub fn new(base: &str) -> Self {
		Discovery {
			issuer: base.to_string(),
			authorization_endpoint: format!("{}authorize", base).to_string(),
			// authorization_endpoint: "http://localhost:8080/authorize".to_string(),
			token_endpoint: format!("{}token", base).to_string(),
			userinfo_endpoint: format!("{}userinfo", base).to_string(),
			jwks_uri: format!("{}jwks", base).to_string(),

			scopes_supported: vec!["openid".to_string()],
			response_types_supported: vec!["code".to_string(), "id_token".to_string(), "id_token token".to_string()],
			id_token_signing_alg_values_supported: vec!["RS256".to_string()],
			userinfo_signing_alg_values_supported: vec!["none".to_string()],

			// TODO: What are these?
			claims_supported: vec!["sub".to_string()],

			// TODO: Why only public? is pairwise a pain?
			subject_types_supported: vec!["public".to_string()],
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, FromRow)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: String,
	pub state: Option<String>,
}

impl AuthorizeRequest {
	pub async fn generate_code(&self, db: &SqlitePool, email: &str) -> Result<OIDCSession> {
		OIDCSession::generate(db, email.to_string(), self.clone()).await
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenRequest {
	pub grant_type: String,
	pub code: String,
	pub client_id: Option<String>,
	pub client_secret: Option<String>,
	// OAuth 2.0 allows for empty redirect_uri
	pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenResponse {
	pub access_token: String,
	pub token_type: String,
	pub expires_in: i64,
	pub id_token: String,
	pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JWTData {
	#[serde(rename = "sub")]
	pub user: String,
	#[serde(rename = "aud")]
	pub client_id: String,
	#[serde(rename = "iss")]
	pub from_url: String,
	#[serde(rename = "exp")]
	pub expires_at: u64,
	pub iat: u64,
}

impl JWTData {
	pub fn new(base_url: &str) -> Self {
		let expiry = Utc::now() + CONFIG.session_duration;
		JWTData {
			user: String::default(),
			client_id: String::default(),
			from_url: base_url.to_string(),
			expires_at: expiry.timestamp() as u64,
			iat: Utc::now().timestamp() as u64,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JWKSResponseItem {
	#[serde(rename = "kty")]
	pub algorithm: String,
	#[serde(rename = "use")]
	pub usage: String,
	#[serde(rename = "kid")]
	pub id: String,
	#[serde(rename = "n")]
	pub modulus: String,
	#[serde(rename = "e")]
	pub exponent: String,
}

impl Default for JWKSResponseItem {
	fn default() -> Self {
		JWKSResponseItem {
			algorithm: "RSA".to_string(),
			usage: "sig".to_string(),
			modulus: String::default(),
			exponent: String::default(),
			id: "default".to_string(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JwksResponse {
	pub keys: Vec<JWKSResponseItem>,
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub email: String,
	pub preferred_username: String,
}
