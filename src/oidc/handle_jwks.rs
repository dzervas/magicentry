use actix_web::{get, web, HttpResponse};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};

use crate::JWT_ALGORITHM;
use crate::error::Response;
use anyhow::Context as _;

#[get("/oidc/jwks")]
pub async fn jwks(key: web::Data<EncodingKey>) -> Response {
	let jwk = Jwk::from_encoding_key(key.as_ref(), JWT_ALGORITHM)
		.context("Failed to create JWK from encoding key")?;
	let resp = JwkSet { keys: vec![jwk] };

	Ok(HttpResponse::Ok().json(resp))
}

#[axum::debug_handler]
pub async fn handle_jwks(axum::extract::State(state): axum::extract::State<crate::AppState>) -> Result<impl axum::response::IntoResponse, crate::error::AppError> {
	let jwk = Jwk::from_encoding_key(&state.key, JWT_ALGORITHM)
		.context("Failed to create JWK from encoding key")?;
	let resp = JwkSet { keys: vec![jwk] };

	Ok(axum::response::Json(resp))
}
