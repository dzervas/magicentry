use actix_web::HttpRequest;
use chrono::{NaiveDateTime, Utc};
use jwt_simple::prelude::*;
use log::warn;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use sqlx::{query, query_as, SqlitePool};

use crate::error::{Error, AppErrorKind};
use crate::oidc::handle_token::JWTData;
use crate::CONFIG;
use crate::user::{random_string, User};
use crate::error::SqlResult;

use super::handle_authorize::AuthorizeRequest;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OIDCClient {
	pub id: String,
	pub secret: String,
	pub redirect_uris: Vec<String>,
	pub realms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, FromRow)]
pub struct OIDCSession {
	pub code: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
	#[sqlx(flatten)]
	pub request: AuthorizeRequest,
}

impl OIDCSession {
	pub async fn generate(db: &SqlitePool, email: String, request: AuthorizeRequest) -> std::result::Result<OIDCSession, Error> {
		let config_client = CONFIG.oidc_clients
			.iter()
			// TODO: Check redirect_uri
			.find(|c| c.id == request.client_id);

		if config_client.is_none() {
			return Err(AppErrorKind::InvalidClientID.into());
		}

		let expires_at = Utc::now()
			.naive_utc()
			.checked_add_signed(CONFIG.session_duration.to_owned())
			.expect("Couldn't add session_duration to Utc::now() - something is wrong with the config");

		let code = random_string();
		query!(
				"INSERT INTO oidc_codes (code, email, expires_at, scope, response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				code,
				email,
				expires_at,
				request.scope,
				request.response_type,
				request.client_id,
				request.redirect_uri,
				request.state,
				request.code_challenge,
				request.code_challenge_method,
			)
			.execute(db)
			.await?;

		Ok(OIDCSession {
			code,
			email,
			expires_at,
			request,
		})
	}

	pub async fn from_code(db: &SqlitePool, code: &str) -> SqlResult<Option<(OIDCClient, OIDCSession)>> {
		println!("Looking for code: {}", code);

		// We need the non-macro query_as to support struct flattening
		let session: Option<OIDCSession> = sqlx::query_as("SELECT * FROM oidc_codes WHERE code = ?")
			.bind(code)
			.fetch_optional(db)
			.await?;

		if let Some(record) = &session {
			query!("DELETE FROM oidc_codes WHERE code = ?", record.code)
				.execute(db)
				.await?;

			if record.expires_at <= Utc::now().naive_utc() {
				return Ok(None);
			}

			let config_client = CONFIG.oidc_clients
				.iter()
				.find(|c|
					c.id == record.request.client_id);

			if let Some(client) = config_client {
				if let Some(redirect_url_enc) = &record.request.redirect_uri {
					// TODO: This can crash
					let redirect_uri = urlencoding::decode(&redirect_url_enc).unwrap().to_string();
					if !client.redirect_uris.contains(&redirect_uri) {
						warn!("Invalid redirect_uri: {} for client_id: {}", redirect_uri, record.request.client_id);
						return Ok(None);
					}
				}

				return Ok(Some((client.clone(), record.clone())));
			}
		}

		Ok(None)
	}

	pub fn get_redirect_url(&self) -> Option<String> {
		let redirect_url = if let Some(redirect_url_enc) = &self.request.redirect_uri {
			urlencoding::decode(&redirect_url_enc).ok()?.to_string()
		} else {
			return None;
		};

		let config_client = CONFIG.oidc_clients
			.iter()
			.find(|c|
				c.id == self.request.client_id &&
				c.redirect_uris.contains(&redirect_url));

		if config_client.is_none() {
			warn!("Invalid redirect_uri: {} for client_id: {}", redirect_url, self.request.client_id);
			return None;
		}

		Some(format!("{}?code={}&state={}",
			redirect_url,
			self.code,
			self.request.state.clone().unwrap_or_default()))
	}

	pub async fn generate_id_token(&self, url: &str, keypair: &RS256KeyPair) -> Result<String, Error> {
		let jwt_data = JWTData {
			user: self.email.clone(),
			client_id: self.request.client_id.clone(),
			..JWTData::new(url)
		};
		println!("JWT Data: {:?}", jwt_data);

		let claims = Claims::with_custom_claims(
			jwt_data,
			Duration::from_millis(
				CONFIG.session_duration
				.num_milliseconds()
				.try_into()
				.map_err(|_| AppErrorKind::InvalidDuration)?));
		let id_token = keypair.sign(claims)?;

		Ok(id_token)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OIDCAuth {
	pub auth: String,
	pub email: String,
	pub expires_at: NaiveDateTime,
}

impl OIDCAuth {
	pub async fn generate(db: &SqlitePool, email: String) -> SqlResult<OIDCAuth> {
		let auth = random_string();
		let expires_at = Utc::now()
			.naive_utc()
			.checked_add_signed(CONFIG.session_duration.to_owned())
			.expect("Couldn't add session_duration to Utc::now() - something is wrong with the config");

		query!(
				"INSERT INTO oidc_auth (auth, email, expires_at) VALUES (?, ?, ?)",
				auth,
				email,
				expires_at
			)
			.execute(db)
			.await?;

		Ok(OIDCAuth {
			auth,
			email,
			expires_at,
		})
	}

	pub async fn from_request(db: &SqlitePool, req: HttpRequest) -> SqlResult<Option<User>> {
		let auth_header = if let Some(header) = req.headers().get("Authorization") {
			header
		} else {
			return Ok(None)
		};

		let auth_header_str = if let Ok(header_str) = auth_header.to_str() {
			header_str
		} else {
			return Ok(None)
		};

		let auth_header_parts = auth_header_str.split_whitespace().collect::<Vec<&str>>();

		if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
			return Ok(None)
		}

		let auth = if let Some(auth) = auth_header_parts.get(1) {
			auth
		} else {
			return Ok(None)
		};

		Self::get_user(db, auth).await
	}

	pub async fn get_user(db: &SqlitePool, auth: &str) -> SqlResult<Option<User>> {
		let auth_res = query_as!(OIDCAuth, "SELECT * FROM oidc_auth WHERE auth = ?", auth)
			.fetch_optional(db)
			.await?;

		if let Some(record) = auth_res {
			if record.expires_at <= Utc::now().naive_utc() {
				query!("DELETE FROM oidc_auth WHERE auth = ?", auth)
					.execute(db)
					.await?;
				return Ok(None)
			}

			return Ok(User::from_config(&record.email));
		}
		Ok(None)
	}
}
