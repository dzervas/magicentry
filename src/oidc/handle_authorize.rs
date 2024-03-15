use actix_session::Session;
use actix_web::{get, post, web, HttpResponse, Responder};
use log::info;
use sqlx::FromRow;
use sqlx::SqlitePool;
use jwt_simple::prelude::*;

use crate::error::Error;
use crate::error::{AppErrorKind, Response};
use crate::user::User;
use crate::AUTHORIZATION_COOKIE;

use super::model::OIDCSession;

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

async fn authorize(session: Session, db: web::Data<SqlitePool>, auth_req: AuthorizeRequest) -> Response {
	info!("Beginning OIDC flow for {}", auth_req.client_id);
	// TODO: Can you inject stuff?
	session.insert(AUTHORIZATION_COOKIE, auth_req.clone()).unwrap();

	let user = if let Some(user) = User::from_session(&db, session).await? {
		user
	} else {
		let target_url = format!("/login?{}", serde_qs::to_string(&auth_req)?);
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish())
	};

	let oidc_session = auth_req.generate_session_code(&db, user.email.as_str()).await?;

	// TODO: Check the state with the cookie for CSRF
	let redirect_url = oidc_session.get_redirect_url().ok_or(AppErrorKind::IncorrectRedirectUrl)?;
	Ok(HttpResponse::Found()
		.append_header(("Location", redirect_url.as_str()))
		.finish())
	// Either send to ?code=<code>&state=<state>
	// Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(session: Session, db: web::Data<SqlitePool>, data: web::Query<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(session: Session, db: web::Data<SqlitePool>, data: web::Form<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
}
