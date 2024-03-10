use actix_session::Session;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use sqlx::SqlitePool;
use jwt_simple::prelude::*;

use crate::oidc_model::{OIDCAuth, OIDCSession};
use crate::user::{User, Result};
use crate::{Response, LISTEN_HOSTNAME, LISTEN_PORT, SESSION_DURATION};
use crate::config;

pub async fn init(db: &SqlitePool) -> RS256KeyPair {
	if let Some(keypair) = config::ConfigKV::get(&db, "jwt_keypair").await {
		RS256KeyPair::from_pem(&keypair).unwrap()
	} else {
		let keypair = RS256KeyPair::generate(4096).unwrap();
		let keypair_pem = keypair.to_pem().unwrap();

		config::ConfigKV::set(&db, "jwt_keypair", &keypair_pem).await.unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		keypair
	}
	.with_key_id("default")
}

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

impl Default for Discovery {
	fn default() -> Self {
		let base = format!("http://{}:{}", LISTEN_HOSTNAME.as_str(), LISTEN_PORT.as_str());
		Discovery {
			issuer: base.to_string(),
			authorization_endpoint: format!("{}/authorize", base).to_string(),
			// authorization_endpoint: "http://localhost:8080/authorize".to_string(),
			token_endpoint: format!("{}/token", base).to_string(),
			userinfo_endpoint: format!("{}/userinfo", base).to_string(),
			jwks_uri: format!("{}/jwks", base).to_string(),

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


#[get("/.well-known/openid-configuration")]
pub async fn configuration() -> impl Responder {
	let discovery = Discovery::default();
	HttpResponse::Ok().json(discovery)
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

async fn authorize(session: Session, db: web::Data<SqlitePool>, data: AuthorizeRequest) -> Response {
	session.insert("oidc_authorize", data.clone()).unwrap();

	let user = if let Some(user) = User::from_session(&db, session).await? {
		user
	} else {
		let target_url = format!("/login?{}", serde_qs::to_string(&data).unwrap());
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish())
	};

	let oidc_session = data.generate_code(&db, user.email.as_str()).await?;

	// TODO: Check the state with the cookie for CSRF
	// XXX: Open redirect
	let redirect_url = oidc_session.get_redirect_url();
	Ok(HttpResponse::Found()
		.append_header(("Location", redirect_url.as_str()))
		.finish())
	// Either send to ?code=<code>&state=<state>
	// Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/authorize")]
pub async fn authorize_get(session: Session, db: web::Data<SqlitePool>, data: web::Query<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
}

#[post("/authorize")]
pub async fn authorize_post(session: Session, db: web::Data<SqlitePool>, data: web::Form<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
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

impl Default for JWTData {
	fn default() -> Self {
		let expiry = Utc::now() + SESSION_DURATION.to_owned();
		JWTData {
			user: String::default(),
			client_id: String::default(),
			from_url: format!("http://{}:{}", LISTEN_HOSTNAME.as_str(), LISTEN_PORT.as_str()).to_string(),
			expires_at: expiry.timestamp() as u64,
			iat: Utc::now().timestamp() as u64,
		}
	}
}


#[post("/token")]
pub async fn token(db: web::Data<SqlitePool>, data: web::Form<TokenRequest>, key: web::Data<RS256KeyPair>) -> Response {
	let session = if let Some(session) = OIDCSession::from_code(&db, &data.code).await? {
		session
	} else {
		return Ok(HttpResponse::BadRequest().finish());
	};

	// XXX: Check client secret
	let jwt_data = JWTData {
		user: session.email.clone(),
		client_id: session.request.client_id.clone(),
		..Default::default()
	};

	let claims = Claims::with_custom_claims(jwt_data, Duration::from_millis(SESSION_DURATION.num_milliseconds().try_into().unwrap()));
	let id_token = key.as_ref().sign(claims).unwrap();

	let access_token = OIDCAuth::generate(&db, session.email.clone()).await?.auth;

	Ok(HttpResponse::Ok().json(TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in: SESSION_DURATION.num_seconds(),
		id_token,
		refresh_token: None,
	}))
	// Either send to ?access_token=<token>&token_type=<type>&expires_in=<seconds>&refresh_token=<token>&id_token=<token>
	// Or send to ?error=<error>&error_description=<error_description>
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JwksResponseItem {
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

impl Default for JwksResponseItem {
	fn default() -> Self {
		JwksResponseItem {
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
	keys: Vec<JwksResponseItem>,
}

#[get("/jwks")]
pub async fn jwks(key: web::Data<RS256KeyPair>) -> impl Responder {
	let comp = key.as_ref().public_key().to_components();

	let item = JwksResponseItem {
		modulus: Base64::encode_to_string(comp.n).unwrap(),
		exponent: Base64::encode_to_string(comp.e).unwrap(),
		..Default::default()
	};

	let resp = JwksResponse {
		keys: vec![item],
	};

	HttpResponse::Ok().json(resp)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserInfoResponse {
	#[serde(rename = "sub")]
	pub user: String,
	pub email: String,
	pub preferred_username: String,
}

#[get("/userinfo")]
pub async fn userinfo(db: web::Data<SqlitePool>, req: HttpRequest) -> impl Responder {
	let auth_header = req.headers().get("Authorization").unwrap();
	let auth_header_parts = auth_header.to_str().unwrap().split_whitespace().collect::<Vec<&str>>();

	if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
		return HttpResponse::BadRequest().finish()
	}

	let auth = auth_header_parts[1];

	if let Ok(Some(user)) = OIDCAuth::get_user(&db, auth).await {
		let alias = if let Some(alias) = user.alias.clone() {
			alias
		} else {
			user.email.clone()
		};

		let resp = UserInfoResponse {
			user: user.email.clone(),
			email: user.email.clone(),
			preferred_username: alias,
		};

		HttpResponse::Ok().json(resp)
	} else {
		HttpResponse::Unauthorized().finish()
	}
}
