use actix_web::dev::ConnectionInfo;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::config::ConfigFile;
use crate::error::{OidcError, ProxyError, Response};
use anyhow::Context as _;
use crate::saml::authn_request::AuthnRequest;
use crate::secret::BrowserSessionSecret;
use crate::pages::{AuthorizePage, Page};
use crate::CONFIG;

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
	conn: ConnectionInfo,
	web::Query(data): web::Query<SAMLRequest>,
	browser_session_opt: Option<BrowserSessionSecret>
) -> Response {
	let authn_request = AuthnRequest::from_encoded_string(&data.request)
		.context("Failed to decode SAML authentication request")?;

	let Some(browser_session) = browser_session_opt else {
		let base_url = ConfigFile::url_from_request(conn).await;
		let mut target_url = url::Url::parse(&base_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut()
			.append_pair("saml", &serde_json::to_string(&data)
				.context("Failed to serialize SAML request for query parameter")?);

		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url.as_str()))
			.finish());
	};

	let config = CONFIG.read().await;
	let service = config.services.from_saml_entity_id(&authn_request.issuer)
		.ok_or(ProxyError::InvalidSAMLRedirectUrl)?;

	if !service.is_user_allowed(browser_session.user()) {
		tracing::warn!("User {} is not allowed to access SAML service {}", browser_session.user().email, service.name);
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish());
	}

	let mut response = authn_request.to_response(
		&format!("{}/saml/metadata", &config.external_url),
		browser_session.user()
	);

	tracing::info!("Starting SAML flow for user: {}", browser_session.user().email);

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
