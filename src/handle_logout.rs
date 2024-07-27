use std::borrow::Cow;

use actix_session::Session;
use actix_web::{get, web, HttpResponse};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::token::SessionToken;
use crate::SESSION_COOKIE;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogoutRequest {
	post_logout_redirect_uri: Option<String>,
}

#[get("/logout")]
async fn logout(
	req: web::Query<LogoutRequest>,
	session: Session,
	db: web::Data<reindeer::Db>,
) -> Response {
	if let Some(Ok(user_session_id)) = session.remove_as::<String>(SESSION_COOKIE) {
		let token = SessionToken::from_code(&db, &user_session_id).await?;
		token.delete(&db).await?;
	}

	// XXX: Open redirect
	let target_url = if let Some(target) = &req.into_inner().post_logout_redirect_uri {
		urlencoding::decode(&target.clone())
			.unwrap_or_else(|_| {
				warn!("Invalid logout redirect URL: {}", &target);
				Cow::from("/login")
			})
			.to_string()
	} else {
		"/login".to_string()
	};

	Ok(HttpResponse::Found()
		.append_header(("Location", target_url.as_str()))
		.finish())
}
