use actix_web::{get, web, HttpResponse};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::saml::{authn_request, authn_response, utils};

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
	let authn_request = utils::decode_saml_request(&data.request).unwrap();
	debug!("SAML SSO request: {:?}", authn_request);
	let authn_data = quick_xml::de::from_str::<authn_request::AuthnRequest>(&authn_request).unwrap();
	debug!("Parsed SAML AuthnRequest: {:?}", authn_data);

	let response = authn_response::SAMLResponse::create_saml_response(
		&authn_data.id,
		&authn_data.acs_url.unwrap(),
		&authn_data.issuer,
		"dzervas@dzervas.gr",
		Vec::new());

	debug!("SAML Response: {:?}", response);
	let response_str = quick_xml::se::to_string_with_root("samlp:Response", &response).unwrap();

	debug!("SAML Response string: {:?}", response_str);

	Ok(HttpResponse::Ok().json(SAMLRequest {
		request: authn_request,
		relay_state: data.relay_state.clone(),
	}))
}
