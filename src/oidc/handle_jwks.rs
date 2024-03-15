use actix_web::{get, web, HttpResponse};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::Response;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JWKSResponseItem {
	#[serde(rename = "kty")]
	pub algorithm: String,
	#[serde(rename = "use")]
	pub usage: String,
	#[serde(rename = "kid")]
	pub id: String,
	#[serde(rename = "n")]
	pub modulus: String,
	#[serde(rename = "e")]
	pub exponent: String,
}

impl Default for JWKSResponseItem {
	fn default() -> Self {
		JWKSResponseItem {
			algorithm: "RSA".to_string(),
			usage: "sig".to_string(),
			modulus: String::default(),
			exponent: String::default(),
			id: "default".to_string(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JwksResponse {
	pub keys: Vec<JWKSResponseItem>,
}


#[get("/oidc/jwks")]
pub async fn jwks(key: web::Data<RS256KeyPair>) -> Response {
	let comp = key.as_ref().public_key().to_components();

	let item = JWKSResponseItem {
		modulus: Base64::encode_to_string(comp.n)?,
		exponent: Base64::encode_to_string(comp.e)?,
		..Default::default()
	};

	let resp = JwksResponse {
		keys: vec![item],
	};

	Ok(HttpResponse::Ok().json(resp))
}
