use actix_web::dev::ConnectionInfo;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::{Config, LiveConfig};
use crate::error::{OidcError, ProxyError, Response};
use crate::saml::authn_request::AuthnRequest;
use crate::secret::BrowserSessionSecret;
use crate::pages::{AuthorizePage, Page};

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

#[get("/saml/sso")]
pub async fn sso(
	config: LiveConfig,
	conn: ConnectionInfo,
	web::Query(data): web::Query<SAMLRequest>,
	browser_session_opt: Option<BrowserSessionSecret>
) -> Response {
	let authn_request = AuthnRequest::from_encoded_string(&data.request)
		.context("Failed to decode SAML authentication request")?;

	let Some(browser_session) = browser_session_opt else {
		let base_url = Config::url_from_request(conn).await;
		let mut target_url = url::Url::parse(&base_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut()
			.append_pair("saml", &serde_json::to_string(&data)
				.context("Failed to serialize SAML request for query parameter")?);

		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url.as_str()))
			.finish());
	};

	let service = config.services.from_saml_entity_id(&authn_request.issuer)
		.ok_or(ProxyError::InvalidSAMLRedirectUrl)?;

	if !service.is_user_allowed(browser_session.user()) {
		warn!("User {} is not allowed to access SAML service {}", browser_session.user().email, service.name);
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish());
	}

	let mut response = authn_request.to_response(
		&format!("{}/saml/metadata", &config.external_url),
		browser_session.user()
	);

	info!("Starting SAML flow for user: {}", browser_session.user().email);

	response.sign_saml_response(
		&config.get_saml_key()
			.context("Failed to get SAML private key for signing response")?,
		&config.get_saml_cert()
			.context("Failed to get SAML certificate for signing response")?
	)
		.context("Failed to sign SAML response")?;

	drop(config);

	let authorize_page = AuthorizePage {
		client: "test client".to_string(),
		name: browser_session.user().name.clone(),
		username: browser_session.user().username.clone(),
		email: browser_session.user().email.clone(),
		saml_response_data: Some(response.to_encoded_string()?),
		saml_relay_state: Some(data.relay_state.clone().unwrap_or_default()),
		saml_acs: Some(authn_request.acs_url.clone()),
		link: None,
	}.render().await;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(authorize_page.into_string()))
}

#[axum::debug_handler]
pub async fn handle_sso(
	axum::extract::State(state): axum::extract::State<crate::AppState>,
	browser_session_opt: Option<BrowserSessionSecret>,
	axum::extract::Query(data): axum::extract::Query<SAMLRequest>,
) -> Result<impl axum::response::IntoResponse, crate::error::AppError>  {
	let config: LiveConfig = state.config.into();

	let authn_request = AuthnRequest::from_encoded_string(&data.request)?;

	let Some(browser_session) = browser_session_opt else {
		// TODO: Proper SAML errors
		// TODO: relative redirects
		let mut target_url = url::Url::parse(&config.external_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut()
			.append_pair("saml", &serde_json::to_string(&data)
				.context("Failed to serialize SAML request for query parameter")?);

		return Ok(axum::response::Redirect::temporary(target_url.as_ref()));
	};

	let service = config.services.from_saml_entity_id(&authn_request.issuer)
		.ok_or(ProxyError::InvalidSAMLRedirectUrl)?;

	if !service.is_user_allowed(browser_session.user()) {
		warn!("User {} is not allowed to access SAML service {}", browser_session.user().email, service.name);
		return Ok(axum::response::Redirect::temporary("/login"));
	}

	let mut response = authn_request.to_response(
		&format!("{}/saml/metadata", &config.external_url),
		browser_session.user()
	);

	info!("Starting SAML flow for user: {}", browser_session.user().email);

	response.sign_saml_response(
		&config.get_saml_key()
			.context("Failed to get SAML private key for signing response")?,
		&config.get_saml_cert()
			.context("Failed to get SAML certificate for signing response")?
	)
		.context("Failed to sign SAML response")?;

	Ok(axum::response::Redirect::temporary("/"))
}
