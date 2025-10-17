use actix_web::{post, web, HttpRequest, HttpResponse};
use actix_web_httpauth::extractors::basic::BasicAuth;
use chrono::Utc;
use jwt_simple::algorithms::RS256KeyPair;
use jwt_simple::reexports::ct_codecs::{Base64UrlSafeNoPadding, Encoder as _};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppErrorKind, Response};
use crate::secret::OIDCAuthCodeSecret;
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

/// Implementation of <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JWTData {
	#[serde(rename = "sub")]
	pub user: String,
	#[serde(rename = "aud")]
	pub client_id: String,
	#[serde(rename = "iss")]
	pub from_url: String,
	#[serde(rename = "exp")]
	pub expires_at: i64,
	pub iat: i64,

	/// String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	/// The value is passed through unmodified from the Authentication Request to the ID Token.
	/// If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to
	/// the value of the nonce parameter sent in the Authentication Request.
	/// If present in the Authentication Request, Authorization Servers MUST include a nonce Claim
	/// in the ID Token with the Claim Value being the nonce value sent in the Authentication Request.
	/// Authorization Servers SHOULD perform no other processing on nonce values used.
	/// The nonce value is a case-sensitive string.
	pub nonce: Option<String>,

	// Additional claims
	pub name: String,
	pub nickname: String,
	pub email: String,
	pub email_verified: bool,
	pub preferred_username: String,
}

impl JWTData {
	pub async fn new(base_url: String, nonce: Option<String>) -> Self {
		let expiry = {
			let config = CONFIG.read().await;
			Utc::now() + config.session_duration
		};

		Self {
			user: String::default(),
			client_id: String::default(),
			from_url: base_url,
			expires_at: expiry.timestamp(),
			iat: Utc::now().timestamp(),
			nonce,

			name: String::default(),
			nickname: String::default(),
			email: String::default(),
			email_verified: true,
			preferred_username: String::default(),
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
	db: web::Data<crate::Database>,
	web::Form(token_req): web::Form<TokenRequest>,
	jwt_keypair: web::Data<RS256KeyPair>,
	basic: Option<BasicAuth>,
) -> Response {
	// This is a too long function.
	// It handles the 3 cases of sending an OIDC token OR turning an authorization code into a token
	debug!("Token request: {token_req:?}");

	let oidc_authcode = OIDCAuthCodeSecret::try_from_string(token_req.code, &db).await?;
	let auth_req = oidc_authcode.child_metadata();

	let client_id = basic.clone()
		.map_or_else(
			|| auth_req.client_id.clone(),
			|basic_creds| basic_creds.user_id().to_string()
		);

	let config = CONFIG.read().await;
	let mut service = config
		.services
		.from_oidc_client_id(&client_id)
		.ok_or(AppErrorKind::InvalidClientID)?;

	let mut oidc = service.oidc.ok_or(AppErrorKind::OIDCNotConfigured)?;

	if let Some(code_verifier) = token_req.code_verifier.clone() {
		// We're using PCRE with code_challenge - code_verifier
		// Client id & secret is not required and only the request origin should be checked
		info!("Responding to PCRE request for client {}", service.name);
		let mut hasher = Sha256::new();
		hasher.update(code_verifier.as_bytes());
		let generated_code_challenge_bytes = hasher.finalize();
		let generated_code_challenge = Base64UrlSafeNoPadding::encode_to_string(generated_code_challenge_bytes)?;

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
			.from_oidc_client_id(&req_client_id)
			.ok_or(AppErrorKind::InvalidClientID)?;

		if !service.is_user_allowed(oidc_authcode.user()) {
			return Err(AppErrorKind::Unauthorized.into());
		}

		oidc = service.oidc.ok_or(AppErrorKind::OIDCNotConfigured)?;

		if oidc.client_id != req_client_id || oidc.client_secret != req_client_secret {
			return Err(AppErrorKind::InvalidClientSecret.into());
		}
	} else {
		return Err(AppErrorKind::NoClientCredentialsProvided.into());
	}


	let base_url = config.url_from_request(&req);
	let id_token = auth_req
		.generate_id_token(oidc_authcode.user(), base_url, jwt_keypair.as_ref())
		.await?;
	let oidc_token = oidc_authcode.exchange_sibling(&db).await?;

	let response = TokenResponse {
		access_token: oidc_token.code().to_str_that_i_wont_print().to_owned(),
		token_type: "Bearer".to_string(),
		expires_in: config.session_duration.num_seconds(),
		id_token,
		// TODO: Actually have a refresh token
		refresh_token: Some(String::new()), // Some apps require the field to be populated, even if empty
	};

	Ok(HttpResponse::Ok()
		// TODO: WTF to do with these origins?
		.append_header(("Access-Control-Allow-Origin", "*"))
		.append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
		.append_header(("Access-Control-Allow-Headers", "Content-Type"))
		.json(response))
	// Either respond access_token=<token>&token_type=<type>&expires_in=<seconds>&refresh_token=<token>&id_token=<token>
	// TODO: Send error response
	// Or error=<error>&error_description=<error_description>
}
