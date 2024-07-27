use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use jwt_simple::prelude::*;
use log::info;

use crate::error::Error;
use crate::error::{AppErrorKind, Response};
use crate::oidc::handle_token::JWTData;
use crate::token::{OIDCCodeToken, SessionToken};
use crate::user::User;
use crate::utils::get_partial;
use crate::{AUTHORIZATION_COOKIE, CONFIG};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: Option<String>,
	pub state: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
}

impl AuthorizeRequest {
	pub async fn generate_session_code(
		&self,
		db: &reindeer::Db,
		user: User,
		bound_to: String,
	) -> std::result::Result<OIDCCodeToken, Error> {
		let self_string = String::try_from(self)?;
		OIDCCodeToken::new(db, user, Some(bound_to), Some(self_string)).await
	}

	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = if let Some(redirect_url_enc) = &self.redirect_uri {
			urlencoding::decode(redirect_url_enc).ok()?.to_string()
		} else {
			return None;
		};

		let config = CONFIG.read().await;
		let config_client = config.oidc_clients.iter().find(|c| {
			user.has_any_realm(&c.realms)
				&& c.id == self.client_id
				&& c.redirect_uris.contains(&redirect_url)
		});

		if config_client.is_none() {
			log::warn!(
				"Invalid redirect_uri: {} for client_id: {}",
				redirect_url,
				self.client_id
			);
			return None;
		}

		Some(format!(
			"{}?code={}&state={}",
			redirect_url,
			code,
			self.state.clone().unwrap_or_default()
		))
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
		println!("JWT Data: {:?}", jwt_data);

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

impl TryFrom<String> for AuthorizeRequest {
	type Error = serde_qs::Error;
	fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
		serde_qs::from_str(&value)
	}
}

impl TryFrom<&AuthorizeRequest> for String {
	type Error = serde_qs::Error;
	fn try_from(value: &AuthorizeRequest) -> std::result::Result<Self, Self::Error> {
		serde_qs::to_string(&value)
	}
}

async fn authorize(
	req: HttpRequest,
	session: Session,
	db: web::Data<reindeer::Db>,
	auth_req: AuthorizeRequest,
) -> Response {
	info!("Beginning OIDC flow for {}", auth_req.client_id);

	if let Some(code_challenge_method) = auth_req.code_challenge_method.as_ref() {
		// TODO: Support plain
		if code_challenge_method != "S256" {
			return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
		}

		if auth_req.code_challenge.is_none() {
			return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
		}
	}

	session.insert(AUTHORIZATION_COOKIE, auth_req.clone())?;

	let Ok(token) = SessionToken::from_session(&db, &session).await else {
		let config = CONFIG.read().await;
		let base_url = config.url_from_request(&req);
		let target_url = format!("{}/login?{}", base_url, serde_qs::to_string(&auth_req)?);
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish());
	};

	let oidc_session = auth_req
		.generate_session_code(&db, token.user.clone(), token.code)
		.await?;
	println!("OIDC Session: {:?}", oidc_session);

	// TODO: Check the state with the cookie for CSRF
	let redirect_url = auth_req
		.get_redirect_url(&oidc_session.code, &oidc_session.user)
		.await
		.ok_or(AppErrorKind::InvalidRedirectUri)?;
	let redirect_url_uri = redirect_url.parse::<Uri>()?;
	let redirect_url_scheme = redirect_url_uri
		.scheme_str()
		.ok_or(AppErrorKind::InvalidRedirectUri)?;
	let redirect_url_authority = redirect_url_uri
		.authority()
		.ok_or(AppErrorKind::InvalidRedirectUri)?;
	let redirect_url_str = format!("{}://{}", redirect_url_scheme, redirect_url_authority);

	let mut authorize_data = BTreeMap::new();
	authorize_data.insert("name", token.user.name.clone());
	authorize_data.insert("username", token.user.username.clone());
	authorize_data.insert("email", token.user.email.clone());
	authorize_data.insert("client", redirect_url_str.clone());
	authorize_data.insert("link", redirect_url.clone());
	let authorize_page = get_partial("authorize", authorize_data)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(authorize_page))
	// Either send to ?code=<code>&state=<state>
	// Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(
	req: HttpRequest,
	session: Session,
	db: web::Data<reindeer::Db>,
	data: web::Query<AuthorizeRequest>,
) -> impl Responder {
	authorize(req, session, db, data.into_inner()).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(
	req: HttpRequest,
	session: Session,
	db: web::Data<reindeer::Db>,
	data: web::Form<AuthorizeRequest>,
) -> impl Responder {
	authorize(req, session, db, data.into_inner()).await
}
