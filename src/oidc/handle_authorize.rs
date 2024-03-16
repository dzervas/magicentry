use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::HttpRequest;
use actix_web::{get, post, web, HttpResponse, Responder};
use formatx::formatx;
use log::info;
use sqlx::FromRow;
use sqlx::SqlitePool;
use jwt_simple::prelude::*;

use crate::error::Error;
use crate::error::{AppErrorKind, Response};
use crate::user::User;
use crate::{get_partial, AUTHORIZATION_COOKIE, CONFIG};

use super::model::OIDCSession;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, FromRow)]
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
	pub async fn generate_session_code(&self, db: &SqlitePool, email: &str) -> std::result::Result<OIDCSession, Error> {
		OIDCSession::generate(db, email.to_string(), self.clone()).await
	}
}

async fn authorize(req: HttpRequest, session: Session, db: web::Data<SqlitePool>, auth_req: AuthorizeRequest) -> Response {
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

	let user = if let Some(user) = User::from_session(&db, session).await? {
		user
	} else {
		let base_url = CONFIG.url_from_request(&req);
		let target_url = format!("{}/login?{}", base_url, serde_qs::to_string(&auth_req)?);
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish())
	};

	let oidc_session = auth_req.generate_session_code(&db, user.email.as_str()).await?;

	// TODO: Check the state with the cookie for CSRF
	let redirect_url = oidc_session.get_redirect_url().ok_or(AppErrorKind::InvalidRedirectUri)?;
	let authorize_page_str = get_partial("authorize");
	let authorize_page = formatx!(
		authorize_page_str,
		email = &user.email,
		client = "TODO",
		link = redirect_url
	)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(authorize_page))
	// Either send to ?code=<code>&state=<state>
	// Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(req: HttpRequest, session: Session, db: web::Data<SqlitePool>, data: web::Query<AuthorizeRequest>) -> impl Responder {
	authorize(req, session, db, data.into_inner()).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(req: HttpRequest, session: Session, db: web::Data<SqlitePool>, data: web::Form<AuthorizeRequest>) -> impl Responder {
	authorize(req, session, db, data.into_inner()).await
}
