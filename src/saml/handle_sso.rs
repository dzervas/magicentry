use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::{get, web, HttpResponse};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::saml::authn_request::AuthnRequest;
use crate::token::SessionToken;
use crate::utils::get_partial;

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
pub async fn sso(data: web::Query<SAMLRequest>, session: Session, db: web::Data<reindeer::Db>) -> Response {
	let Ok(token) = SessionToken::from_session(&db, &session).await else {
		// TODO: SAML data are lost during redirect
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish());
	};

	let authn_request = AuthnRequest::from_encoded_string(&data.request)?;
	debug!("Parsed SAML AuthnRequest: {:?}", authn_request);

	let mut response = authn_request.to_response("http://localhost:8181/saml/metadata", "dzervas@dzervas.gr");

	debug!("SAML Response: {:?}", response);

	response.sign_saml_response(
		&std::fs::read_to_string("saml_key.pem").unwrap(),
		&std::fs::read_to_string("saml_cert.pem").unwrap()
	).unwrap();
	debug!("Signed SAML Response: {:?}", response);

	let mut authorize_data = BTreeMap::new();
	authorize_data.insert("name", token.user.name.clone());
	authorize_data.insert("username", token.user.username.clone());
	authorize_data.insert("email", token.user.email.clone());
	authorize_data.insert("client", "test client".to_string());
	authorize_data.insert("samlACS", authn_request.acs_url.clone().unwrap());
	authorize_data.insert("samlResponseData", response.to_encoded_string().unwrap());
	authorize_data.insert("samlRelayState", data.relay_state.clone());
	debug!("\n\n{}\n\n", authorize_data.get_key_value("samlResponseData").unwrap().1);
	let authorize_page = get_partial("authorize", authorize_data)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(authorize_page))
}
