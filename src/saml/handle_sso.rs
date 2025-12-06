use anyhow::Context as _;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::AppState;
use crate::config::LiveConfig;
use crate::error::{AppError, OidcError, ProxyError};
use crate::saml::authn_request::AuthnRequest;
use crate::secret::BrowserSessionSecret;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SAMLRequest {
	#[serde(rename = "SAMLRequest")]
	pub request: String,
	#[serde(rename = "RelayState")]
	pub relay_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SAMLResponse {
	#[serde(rename = "SAMLResponse")]
	pub response: String,
	#[serde(rename = "RelayState")]
	pub relay_state: String,
}

#[axum::debug_handler]
pub async fn handle_sso(
	config: LiveConfig,
	State(_state): State<AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	Query(data): Query<SAMLRequest>,
) -> Result<impl IntoResponse, AppError> {
	let authn_request = AuthnRequest::from_encoded_string(&data.request)?;

	let Some(browser_session) = browser_session_opt else {
		// TODO: Proper SAML errors
		// TODO: relative redirects
		let mut target_url =
			url::Url::parse(&config.external_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut().append_pair(
			"saml",
			&serde_json::to_string(&data)
				.context("Failed to serialize SAML request for query parameter")?,
		);

		return Ok(Redirect::to(target_url.as_ref()));
	};

	let service = config
		.services
		.from_saml_entity_id(&authn_request.issuer)
		.ok_or(ProxyError::InvalidSAMLRedirectUrl)?;

	if !service.is_user_allowed(browser_session.user()) {
		warn!(
			"User {} is not allowed to access SAML service {}",
			browser_session.user().email,
			service.name
		);
		return Ok(Redirect::to("/login"));
	}

	let mut response = authn_request.to_response(
		&format!("{}/saml/metadata", &config.external_url),
		browser_session.user(),
	);

	info!(
		"Starting SAML flow for user: {}",
		browser_session.user().email
	);

	response
		.sign_saml_response(
			&config
				.get_saml_key()
				.context("Failed to get SAML private key for signing response")?,
			&config
				.get_saml_cert()
				.context("Failed to get SAML certificate for signing response")?,
		)
		.context("Failed to sign SAML response")?;

	Ok(Redirect::to("/"))
}
