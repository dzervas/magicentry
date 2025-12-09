use anyhow::Context as _;
use axum::http::Uri;
use axum::response::IntoResponse;
use tracing::info;

use crate::AUTHORIZATION_COOKIE;
use crate::config::LiveConfig;
use crate::error::OidcError;
use crate::pages::{AuthorizePage, Page};
use crate::secret::{BrowserSessionSecret, OIDCAuthCodeSecret};

use super::AuthorizeRequest;

#[axum::debug_handler]
pub async fn handle_authorize_get(
	config: LiveConfig,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	jar: axum_extra::extract::CookieJar,
	axum::extract::Query(auth_req): axum::extract::Query<AuthorizeRequest>,
) -> Result<(axum_extra::extract::CookieJar, axum::response::Response), crate::error::AppError> {
	handle_authorize(config, state, browser_session_opt, jar, auth_req).await
}

#[axum::debug_handler]
pub async fn handle_authorize_post(
	config: LiveConfig,
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	jar: axum_extra::extract::CookieJar,
	axum::extract::Form(auth_req): axum::extract::Form<AuthorizeRequest>,
) -> Result<(axum_extra::extract::CookieJar, axum::response::Response), crate::error::AppError> {
	handle_authorize(config, state, browser_session_opt, jar, auth_req).await
}

pub async fn handle_authorize(
	config: LiveConfig,
	state: crate::AppState,
	browser_session_opt: Option<BrowserSessionSecret>,
	jar: axum_extra::extract::CookieJar,
	auth_req: AuthorizeRequest,
) -> Result<(axum_extra::extract::CookieJar, axum::response::Response), crate::error::AppError> {
	info!("Beginning OIDC flow for {}", auth_req.client_id);
	let external_url = config.external_url.clone();

	let Some(browser_session) = browser_session_opt else {
		let mut target_url =
			url::Url::parse(&external_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut().append_pair(
			"oidc",
			&serde_json::to_string(&auth_req).with_context(|| {
				format!(
					"Failed to serialize OIDC auth request for client {}",
					auth_req.client_id
				)
			})?,
		);

		return Ok((
			jar,
			axum::response::Redirect::to(target_url.as_ref()).into_response(),
		));
	};

	let oidc_authcode =
		OIDCAuthCodeSecret::new_child(browser_session, auth_req.clone(), &config, &state.db)
			.await?;

	// TODO: Check the state with the cookie for CSRF
	// TODO: WTF?
	let redirect_url = auth_req
		.get_redirect_url(
			&oidc_authcode.code().to_str_that_i_wont_print(),
			oidc_authcode.user(),
		)
		.await
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_uri = redirect_url
		.parse::<Uri>()
		.context("Failed to parse redirect URL as URI")?;
	let redirect_url_scheme = redirect_url_uri
		.scheme_str()
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_authority = redirect_url_uri
		.authority()
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_str = format!("{redirect_url_scheme}://{redirect_url_authority}");

	let authorize_page = AuthorizePage {
		client: redirect_url_str,
		name: oidc_authcode.user().name.clone(),
		username: oidc_authcode.user().username.clone(),
		email: oidc_authcode.user().email.clone(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some(redirect_url),
	}
	.render()
	.await;

	let cookie = axum_extra::extract::cookie::Cookie::build((
		AUTHORIZATION_COOKIE,
		serde_json::to_string(&auth_req).with_context(|| {
			format!(
				"Failed to serialize OIDC auth request for cookie: {}",
				auth_req.client_id
			)
		})?,
	))
	.http_only(true)
	.path("/")
	.build();

	Ok((jar.add(cookie), authorize_page.into_response()))
}
