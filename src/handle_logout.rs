use std::borrow::Cow;

use actix_web::{get, web, HttpResponse};
use tracing::warn;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::secret::BrowserSessionSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
	post_logout_redirect_uri: Option<String>,
}

#[get("/logout")]
async fn logout(
	web::Query(req): web::Query<LogoutRequest>,
	db: web::Data<crate::Database>,
	browser_session: BrowserSessionSecret,
) -> Response {
	browser_session.delete(&db).await?;

	// XXX: Open redirect
	let target_url = req.post_logout_redirect_uri
		.as_ref()
		.map_or_else(|| "/login".to_string(), |target| urlencoding::decode(&target.clone())
			.unwrap_or_else(|_| {
				warn!("Invalid logout redirect URL: {}", &target);
				Cow::from("/login")
			})
			.to_string());

	Ok(HttpResponse::Found()
		.append_header(("Location", target_url.as_str()))
		.cookie(BrowserSessionSecret::unset_cookie())
		.finish())
}

#[axum::debug_handler]
pub async fn handle_logout(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session: BrowserSessionSecret,
	axum::extract::Query(post_logout_redirect_uri): axum::extract::Query<Option<String>>,
) -> Result<impl axum::response::IntoResponse, axum::http::StatusCode>  {
	browser_session.delete(&state.db).await.unwrap();

	// XXX: Open redirect
	let target_url = post_logout_redirect_uri
		.as_ref()
		.map_or_else(|| "/login".to_string(), |target| urlencoding::decode(&target.clone())
			.unwrap_or_else(|_| {
				warn!("Invalid logout redirect URL: {}", &target);
				Cow::from("/login")
			})
			.to_string());

	// TODO: Remove the cookie as well
	Ok(axum::response::Redirect::to(&target_url))
}
