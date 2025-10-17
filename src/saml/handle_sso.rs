use std::collections::BTreeMap;

use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Response};
use crate::saml::authn_request::AuthnRequest;
use crate::secret::BrowserSessionSecret;
use crate::utils::get_partial;
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
	req: HttpRequest,
	web::Query(data): web::Query<SAMLRequest>,
	browser_session_opt: Option<BrowserSessionSecret>
) -> Response {
	let authn_request = AuthnRequest::from_encoded_string(&data.request)?;
	let config = CONFIG.read().await;

	let Some(browser_session) = browser_session_opt else {
		let base_url = config.url_from_request(&req);
		drop(config);
		let mut target_url = url::Url::parse(&base_url).map_err(|_| AppErrorKind::InvalidOIDCRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut()
			.append_pair("saml", &serde_json::to_string(&data)?);

		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url.as_str()))
			.finish());
	};

	let service = config.services.from_saml_entity_id(&authn_request.issuer)
		.ok_or(AppErrorKind::InvalidSAMLRedirectUrl)?;

	if !service.is_user_allowed(browser_session.user()) {
		log::warn!("User {} is not allowed to access SAML service {}", browser_session.user().email, service.name);
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish());
	}

	let mut response = authn_request.to_response(
		&format!("{}/saml/metadata", &config.external_url),
		browser_session.user()
	);

	log::info!("Starting SAML flow for user: {}", browser_session.user().email);

	response.sign_saml_response(
		&config.get_saml_key()?,
		&config.get_saml_cert()?
	)?;

	drop(config);

	let mut authorize_data = BTreeMap::new();
	authorize_data.insert("name", browser_session.user().name.clone());
	authorize_data.insert("username", browser_session.user().username.clone());
	authorize_data.insert("email", browser_session.user().email.clone());
	authorize_data.insert("client", "test client".to_string());
	authorize_data.insert("samlACS", authn_request.acs_url.clone());
	authorize_data.insert("samlResponseData", response.to_encoded_string()?);
	authorize_data.insert("samlRelayState", data.relay_state.clone().unwrap_or_default());
	let authorize_page = get_partial::<()>("authorize", authorize_data, None)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(authorize_page))
}
