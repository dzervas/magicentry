use actix_web::{get, web, HttpResponse};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::saml::authn_request::AuthnRequest;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SAMLRequest {
	#[serde(rename = "SAMLRequest")]
	pub request: String,
	#[serde(rename = "RelayState")]
	pub relay_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SAMLResponse {
	#[serde(rename = "SAMLResponse")]
	pub response: String,
	#[serde(rename = "RelayState")]
	pub relay_state: String,
}

#[get("/saml/sso")]
pub async fn sso(data: web::Query<SAMLRequest>) -> Response {
	let authn_request = AuthnRequest::from_encoded_string(&data.request)?;
	debug!("Parsed SAML AuthnRequest: {:?}", authn_request);

	let response = authn_request.to_response("http://localhost:8181/saml/metadata", "dzervas@dzervas.gr");

	debug!("SAML Response: {:?}", response);
	let response_str = quick_xml::se::to_string_with_root("samlp:Response", &response).unwrap();

	debug!("SAML Response string: {:?}", response_str);

	Ok(HttpResponse::Ok().json(SAMLRequest {
		request: response_str,
		relay_state: data.relay_state.clone(),
	}))
}
