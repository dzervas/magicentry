use chrono::Utc;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use sqlx::SqlitePool;

use crate::error::Error;
use crate::CONFIG;

use super::model::*;

fn serialize_vec_with_space<S: Serializer>(vec: &Vec<&str>, serializer: S) -> std::result::Result<S::Ok, S::Error> {
	serializer.serialize_str(&vec.join(" "))
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Discovery<'a> {
	pub issuer: &'a str,

	// These are String because they get constructed with format!
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub userinfo_endpoint: String,
	pub jwks_uri: String,

	#[serde(serialize_with = "serialize_vec_with_space")]
	pub scopes_supported: Vec<&'a str>,
	pub response_types_supported: Vec<&'a str>,
	pub id_token_signing_alg_values_supported: Vec<&'a str>,
	pub userinfo_signing_alg_values_supported: Vec<&'a str>,
	// pub token_endpoint_auth_methods_supported: Vec<&'a str>,
	pub claims_supported: Vec<&'a str>,

	pub subject_types_supported: Vec<&'a str>,
}

impl<'a> Discovery<'a> {
	pub fn new(base: &'a str) -> Self {
		Discovery {
			issuer: base,

			authorization_endpoint: format!("{}oidc/authorize", base),
			token_endpoint: format!("{}oidc/token", base),
			userinfo_endpoint: format!("{}oidc/userinfo", base),
			jwks_uri: format!("{}oidc/jwks", base),

			scopes_supported: vec!["openid", "profile", "email"],
			response_types_supported: vec!["code", "id_token", "id_token token"],
			id_token_signing_alg_values_supported: vec!["RS256"],
			userinfo_signing_alg_values_supported: vec!["none"],
			claims_supported: vec!["sub", "email", "preferred_username", "name"],

			// Pairwise would require a different username per client, too much hassle
			subject_types_supported: vec!["public"],
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, FromRow)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: Option<String>,
	pub state: Option<String>,
	// TODO: code_challenge?
}

impl AuthorizeRequest {
	pub async fn generate_session_code(&self, db: &SqlitePool, email: &str) -> std::result::Result<OIDCSession, Error> {
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
