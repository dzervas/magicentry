use std::borrow::Cow;

use actix_web::{get, web, HttpResponse};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::secret::BrowserSessionSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
	post_logout_redirect_uri: Option<String>,
}

#[get("/logout")]
async fn logout(
	req: web::Query<LogoutRequest>,
	db: web::Data<crate::Database>,
	browser_session: BrowserSessionSecret,
) -> Response {
	browser_session.delete(&db).await?;

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
		.cookie(BrowserSessionSecret::unset_cookie())
		.finish())
}
