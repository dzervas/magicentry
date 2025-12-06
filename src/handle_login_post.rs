//! The login form submission handler - used to handle the login form
//! showed by the [`handle_login`](crate::handle_login) endpoint
//!
//! It handles the magic link generation, sending it to the user (email/webhook)
//! and saving any redirection-related data so that when the user clicks the link,
//! they can be redirected to the right place - used for auth-url/OIDC/SAML

use axum::Form;
use axum::extract::{Query, State};
use axum::response::{IntoResponse as _, Response};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::AppState;
use crate::config::LiveConfig;
use crate::error::AppError;
use crate::pages::{LoginActionPage, Page};
use crate::secret::LoginLinkSecret;
use crate::secret::login_link::LoginLinkRedirect;
use crate::user::User;

/// Used to get the login form data for from the login page
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LoginInfo {
	pub email: String,
}

#[axum::debug_handler]
pub async fn handle_login_post(
	config: LiveConfig,
	State(state): State<AppState>,
	Query(login_redirect): Query<LoginLinkRedirect>,
	Form(form): Form<LoginInfo>,
) -> Result<Response, AppError> {
	let login_action_page = LoginActionPage.render().await;

	// Return 200 to avoid leaking valid emails
	let Some(user) = User::from_email(&config, &form.email) else {
		return Ok(login_action_page.into_response());
	};

	// Generate the magic link
	let link = LoginLinkSecret::new(
		user.clone(),
		login_redirect.into_opt().await,
		&config,
		&state.db,
	)
	.await?;
	let magic_link = config.external_url.clone() + &link.get_login_url();

	#[cfg(debug_assertions)]
	info!("Link: {}", &magic_link);

	state.send_magic_link(&user, &magic_link).await?;
	Ok(login_action_page.into_response())
}
