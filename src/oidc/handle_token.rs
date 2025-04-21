use actix_web::{post, web, HttpRequest, HttpResponse};
use actix_web_httpauth::extractors::basic::BasicAuth;
use chrono::Utc;
use jwt_simple::algorithms::RS256KeyPair;
use jwt_simple::reexports::ct_codecs::{Base64UrlSafeNoPadding, Encoder as _};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppErrorKind, Response};
use crate::oidc::handle_authorize::AuthorizeRequest;
use crate::token::{OIDCBearerToken, OIDCCodeToken};
use crate::{generate_cors_preflight, CONFIG};

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
	pub async fn new(base_url: String) -> Self {
		let config = CONFIG.read().await;
		let expiry = Utc::now() + config.session_duration;
		JWTData {
			user: String::default(),
			client_id: String::default(),
			from_url: base_url,
			expires_at: expiry.timestamp() as u64,
			iat: Utc::now().timestamp() as u64,
		}
	}
}

// While the preflight allows only the allowed origins,
// the actual request is not checked.
// So a browser from a not whitelisted origin shouldn't be able to send
// a request to this endpoint (failed CORS preflight)
// But any other client (a backend from an app) can send a request to this endpoint
// from any origin
generate_cors_preflight!(token_preflight, "/oidc/token", "POST");

#[post("/oidc/token")]
pub async fn token(
	req: HttpRequest,
	db: web::Data<reindeer::Db>,
	token_req: web::Form<TokenRequest>,
	jwt_keypair: web::Data<RS256KeyPair>,
	basic: Option<BasicAuth>,
) -> Response {
	debug!("Token request: {:?}", token_req);

	let session = OIDCCodeToken::from_code(&db, &token_req.code).await?;
	debug!("Session: {:?}", session);
	let auth_req =
	AuthorizeRequest::try_from(session.metadata.ok_or(AppErrorKind::MissingMetadata)?)?;
	let config = CONFIG.read().await;

	let client_id = if let Some(basic_creds) = basic.clone() {
		basic_creds.user_id().to_string()
	} else {
		auth_req.client_id.clone()
	};

	let mut service = config
		.services
		.from_oidc_client_id(&client_id)
		.ok_or(AppErrorKind::InvalidClientID)?;

	let mut oidc = service.oidc.ok_or(AppErrorKind::OIDCNotConfigured)?;

	if let Some(code_verifier) = token_req.code_verifier.clone() {
		// We're using PCRE with code_challenge - code_verifier
		// Client secret is not required and only the request origin should be checked
		info!("Responding to PCRE request for client {}", service.name);
		let mut hasher = Sha256::new();
		hasher.update(code_verifier.as_bytes());
		let generated_code_challenge_bytes = hasher.finalize();
		let generated_code_challenge =
		Base64UrlSafeNoPadding::encode_to_string(generated_code_challenge_bytes)?;

		if oidc.client_id != token_req.client_id.clone().unwrap_or_default() {
			return Err(AppErrorKind::InvalidClientID.into());
		}

		// TODO: We require a client_secret, does that cause any issues?
		if oidc.client_secret != token_req.client_secret.clone().unwrap_or_default() {
			return Err(AppErrorKind::InvalidClientSecret.into());
		}

		if Some(generated_code_challenge) != auth_req.code_challenge {
			return Err(AppErrorKind::InvalidCodeVerifier.into());
		}
	} else if let Some(req_client_secret) = token_req.client_secret.clone() {
		// We're using client_id - client_secret
		info!("Responding to client_secret_post request for client {}", service.name);
		let req_client_id = token_req.client_id.clone().ok_or(AppErrorKind::NoClientID)?;

		if oidc.client_secret != req_client_secret {
			return Err(AppErrorKind::InvalidClientSecret.into());
		}

		if oidc.client_id != req_client_id {
			return Err(AppErrorKind::InvalidClientID.into());
		}
	} else if let Some(basic_creds) = basic {
		// We're using client_id - client_secret over basic auth
		debug!("Responding to client_secret_basic request");
		let req_client_id = basic_creds.user_id().to_string();
		let req_client_secret = basic_creds.password()
			.ok_or(AppErrorKind::NoClientSecret)?
			.to_string();
		service = config
			.services
			.from_oidc_client_id_with_realms(&req_client_id, &session.user)
			.ok_or(AppErrorKind::InvalidClientID)?;
		oidc = service.oidc.ok_or(AppErrorKind::OIDCNotConfigured)?;

		if oidc.client_id != req_client_id || oidc.client_secret != req_client_secret {
			return Err(AppErrorKind::InvalidClientSecret.into());
		}
	} else {
		return Err(AppErrorKind::NoClientCredentialsProvided.into());
	}

	let base_url = config.url_from_request(&req);
	let id_token = auth_req
		.generate_id_token(&session.user, base_url, jwt_keypair.as_ref())
		.await?;
	let access_token = OIDCBearerToken::new(&db, session.user, session.bound_to, None)
		.await?
		.code;

	let response = TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in: config.session_duration.num_seconds(),
		id_token,
		refresh_token: Some(String::new()), // Some apps require the field to be populated, even if empty
	};

	if service.valid_origins.is_empty() {
		return Ok(HttpResponse::Ok().json(response));
	}

	let Some(origin_val) = req.headers().get("Origin") else {
		return Ok(HttpResponse::BadRequest().finish());
	};

	let Ok(origin) = origin_val.to_str() else {
		return Ok(HttpResponse::BadRequest().finish());
	};

	if !service.valid_origins.contains(&origin.to_string()) {
		return Ok(HttpResponse::Forbidden().finish());
	}

	Ok(HttpResponse::Ok()
	.append_header(("Access-Control-Allow-Origin", origin))
	.append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
	.append_header(("Access-Control-Allow-Headers", "Content-Type"))
	.json(response))
	// Either respond access_token=<token>&token_type=<type>&expires_in=<seconds>&refresh_token=<token>&id_token=<token>
	// TODO: Send error response
	// Or error=<error>&error_description=<error_description>
}
