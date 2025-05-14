use std::collections::BTreeMap;

use actix_web::cookie::Cookie;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use jwt_simple::prelude::*;
use log::{debug, info};
use url::Url;

use crate::error::Error;
use crate::error::{AppErrorKind, Response};
use crate::oidc::handle_token::JWTData;
use crate::user::User;
use crate::user_secret::{BrowserSessionSecret, MetadataKind, OIDCAuthCodeSecret};
use crate::utils::get_partial;
use crate::{AUTHORIZATION_COOKIE, CONFIG};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizeRequest {
	pub scope: String,
	pub response_type: String,
	pub client_id: String,
	pub redirect_uri: String,
	pub state: Option<String>,
	pub code_challenge: Option<String>,
	pub code_challenge_method: Option<String>,
}

impl AuthorizeRequest {
	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = Url::parse(&urlencoding::decode(&self.redirect_uri).ok()?).ok()?;

		let config = CONFIG.read().await;

		let Some(service) = config.services.from_oidc_redirect_url(&redirect_url) else {
			log::warn!(
				"Invalid OIDC redirect_uri: {} for client_id: {}",
				redirect_url,
				self.client_id
			);
			return None;
		};

		if !service.is_user_allowed(user) {
			log::warn!(
				"User {} is not allowed to access OIDC redirect_uri: {} for client_id: {}",
				user.email,
				redirect_url,
				self.client_id
			);
			return None;
		}

		// Use the Url type
		Some(
			redirect_url.clone()
				.query_pairs_mut()
				.append_pair("code", code)
				.append_pair("state", &self.state.clone().unwrap_or_default())
				.finish()
				.to_string()
		)
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
		debug!("JWT Data: {:?}", jwt_data);

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

impl MetadataKind for AuthorizeRequest {
	async fn validate(&self, _db: &reindeer::Db) -> crate::error::Result<()> {
		if let Some(code_challenge_method) = self.code_challenge_method.as_ref() {
			// TODO: Support plain
			if code_challenge_method != "S256" {
				return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
			}

			if self.code_challenge.is_none() {
				return Err(AppErrorKind::InvalidCodeChallengeMethod.into());
			}
		}

		Ok(())
	}
}

async fn authorize(
	req: HttpRequest,
	db: web::Data<reindeer::Db>,
	auth_req: AuthorizeRequest,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> Response {
	info!("Beginning OIDC flow for {}", auth_req.client_id);

	let Some(browser_session) = browser_session_opt else {
		let config = CONFIG.read().await;
		let base_url = config.url_from_request(&req);
		let target_url = format!("{}/login?{}", base_url, serde_qs::to_string(&auth_req)?);
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish());
	};

	// let oidc_authcode = auth_req
	// 	.generate_session_code(&db, browser_session.user().clone(), browser_session.code())
	// 	.await?;
	let oidc_authcode = OIDCAuthCodeSecret::new_child(browser_session, auth_req.clone(), &db).await?;

	// TODO: Check the state with the cookie for CSRF
	// TODO: WTF?
	let redirect_url = auth_req
		.get_redirect_url(&oidc_authcode.code().to_str_that_i_wont_print(), &oidc_authcode.user())
		.await
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_uri = redirect_url.parse::<Uri>()?;
	let redirect_url_scheme = redirect_url_uri
		.scheme_str()
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_authority = redirect_url_uri
		.authority()
		.ok_or(AppErrorKind::InvalidOIDCRedirectUrl)?;
	let redirect_url_str = format!("{}://{}", redirect_url_scheme, redirect_url_authority);

	let mut authorize_data = BTreeMap::new();
	authorize_data.insert("name", oidc_authcode.user().name.clone());
	authorize_data.insert("username", oidc_authcode.user().username.clone());
	authorize_data.insert("email", oidc_authcode.user().email.clone());
	authorize_data.insert("client", redirect_url_str.clone());
	authorize_data.insert("link", redirect_url.clone());
	let authorize_page = get_partial::<()>("authorize", authorize_data, None)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.cookie(Cookie::new(AUTHORIZATION_COOKIE, serde_json::to_string(&auth_req)?))
		.body(authorize_page))
	// Either send to ?code=<code>&state=<state>
	// TODO: Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(
	req: HttpRequest,
	db: web::Data<reindeer::Db>,
	data: web::Query<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(req, db, data.into_inner(), browser_session_opt).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(
	req: HttpRequest,
	db: web::Data<reindeer::Db>,
	data: web::Form<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(req, db, data.into_inner(), browser_session_opt).await
}
