use actix_web::HttpRequest;
use actix_web::{post, web, HttpResponse};
use chrono::Utc;
use log::{info, warn};
use sqlx::SqlitePool;
use jwt_simple::prelude::*;

use crate::error::{AppErrorKind, Response};
use crate::CONFIG;

use super::model::{OIDCAuth, OIDCSession};

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

#[post("/oidc/token")]
pub async fn token(req: HttpRequest, db: web::Data<SqlitePool>, req_token: web::Form<TokenRequest>, jwt_keypair: web::Data<RS256KeyPair>) -> Response {
	println!("Token Request: {:?}", req);
	let (client, session) = if let Some(client_session) = OIDCSession::from_code(&db, &req_token.code).await? {
		client_session
	} else {
		#[cfg(debug_assertions)]
		info!("Someone tried to get a token with an invalid invalid OIDC code: {}", req_token.code);
		#[cfg(not(debug_assertions))]
		info!("Someone tried to get a token with an invalid invalid OIDC code");

		return Ok(HttpResponse::BadRequest().finish());
	};

	let req_client_id = req_token.client_id.as_ref().ok_or(AppErrorKind::NoClientID)?;
	let req_client_secret = req_token.client_secret.as_ref().ok_or(AppErrorKind::NoClientSecret)?;

	if
		&client.id != req_client_id ||
		&client.secret != req_client_secret {
		#[cfg(debug_assertions)]
		warn!("Incorrect Client ID ({}) or Secret ({}) for OIDC code: {}", req_client_id, req_client_secret, req_token.code);
		#[cfg(not(debug_assertions))]
		warn!("Incorrect Client ID or Secret for OIDC code");

		return Ok(HttpResponse::BadRequest().finish());
	}

	let jwt_data = JWTData {
		user: session.email.clone(),
		client_id: session.request.client_id.clone(),
		..JWTData::new(&CONFIG.url_from_request(&req))
	};
	println!("JWT Data: {:?}", jwt_data);

	let claims = Claims::with_custom_claims(
		jwt_data,
		Duration::from_millis(
			CONFIG.session_duration
			.num_milliseconds()
			.try_into()
			.map_err(|_| AppErrorKind::InvalidDuration)?));
	let id_token = jwt_keypair.as_ref().sign(claims)?;

	let access_token = OIDCAuth::generate(&db, session.email.clone()).await?.auth;

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
