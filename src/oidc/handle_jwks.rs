use actix_web::{get, web, HttpResponse};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};

use crate::JWT_ALGORITHM;
use crate::error::Response;

#[get("/oidc/jwks")]
pub async fn jwks(key: web::Data<EncodingKey>) -> Response {
	let jwk = Jwk::from_encoding_key(key.as_ref(), JWT_ALGORITHM)?;
	let resp = JwkSet { keys: vec![jwk] };

	Ok(HttpResponse::Ok().json(resp))
}
