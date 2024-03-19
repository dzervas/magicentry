use actix_web::HttpRequest;
use actix_web::{post, web, HttpResponse};
use chrono::Utc;
use jwt_simple::algorithms::RS256KeyPair;
use jwt_simple::reexports::ct_codecs::{Base64UrlSafeNoPadding, Encoder as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::user::{Token, TokenKind, User};
use crate::CONFIG;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TokenRequest {
	pub grant_type: String,
	pub code: String,
	pub client_id: Option<String>,
	pub client_secret: Option<String>,
	pub code_verifier: Option<String>,
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

#[post("/oidc/token")]
pub async fn token(req: HttpRequest, db: web::Data<SqlitePool>, token_req: web::Form<TokenRequest>, jwt_keypair: web::Data<RS256KeyPair>) -> Response {
	#[cfg(debug_assertions)]
	log::info!("Token request: {:?}", token_req);

	let session = Token::from_code(&db, &token_req.code, TokenKind::OIDCCode).await?;
	println!("Session: {:?}", session);
	let auth_req = AuthorizeRequest::try_from(session.metadata.ok_or(AppErrorKind::MissingMetadata)?)?;

	// TODO: Check the request origin
	if let Some(code_verifier) = token_req.code_verifier.clone() {
		// We're using PCRE with code_challenge - code_verifier
		// Client secret is not required and only the request origin should be checked
		let mut hasher = Sha256::new();
		hasher.update(code_verifier.as_bytes());
		let generated_code_challenge_bytes = hasher.finalize().clone();
		let generated_code_challenge = Base64UrlSafeNoPadding::encode_to_string(generated_code_challenge_bytes)?;

		if Some(generated_code_challenge) != auth_req.code_challenge {
			return Err(AppErrorKind::InvalidCodeVerifier.into());
		}
	} else if let Some(req_client_secret) = token_req.client_secret.clone() {
		// We're using client_id - client_secret
		let req_client_id = token_req.client_id.clone().ok_or(AppErrorKind::NoClientID)?;
		let session_client_id = auth_req.client_id.clone();
		let config_client = CONFIG.oidc_clients.iter().find(|c| c.id == session_client_id).ok_or(AppErrorKind::InvalidClientID)?;

		if req_client_id != session_client_id {
			return Err(AppErrorKind::NotMatchingClientID.into());
		}

		if config_client.id != req_client_id || config_client.secret != req_client_secret {
			return Err(AppErrorKind::InvalidClientSecret.into());
		}
	} else {
		return Err(AppErrorKind::NoClientCredentialsProvided.into());
	}

	let base_url = CONFIG.url_from_request(&req);
	let user = User::from_config(&session.user).ok_or(AppErrorKind::InvalidTargetUser)?;
	let id_token = auth_req.generate_id_token(&user, &base_url, jwt_keypair.as_ref()).await?;
	let access_token = Token::new(&db, TokenKind::OIDCBearer, &user, None, None).await?.code;

	Ok(HttpResponse::Ok().json(TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in: CONFIG.session_duration.num_seconds(),
		id_token,
		refresh_token: None,
	}))
	// Either respond access_token=<token>&token_type=<type>&expires_in=<seconds>&refresh_token=<token>&id_token=<token>
	// TODO: Send error response
	// Or error=<error>&error_description=<error_description>
}
