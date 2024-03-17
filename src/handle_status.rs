use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use sqlx::SqlitePool;

use crate::error::{AppErrorKind, Response};
use crate::user::User;
use crate::CONFIG;

#[get("/status")]
async fn status(session: Session, db: web::Data<SqlitePool>) -> Response {
	let user = User::from_session(&db, session).await?.ok_or(AppErrorKind::NotLoggedIn)?;

	Ok(HttpResponse::Ok()
		// TODO: Add realm
		.append_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
		.append_header((CONFIG.auth_url_user_header.as_str(), user.username.unwrap_or_default()))
		.append_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()))
		// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
		.finish())
}
