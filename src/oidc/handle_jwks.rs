use anyhow::Context as _;
use axum::extract::State;
use axum::response::IntoResponse;
use jsonwebtoken::Algorithm;
use jsonwebtoken::jwk::{Jwk, JwkSet};

use crate::AppState;
use crate::error::AppError;

#[axum::debug_handler]
pub async fn handle_jwks(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
	let mut jwk = Jwk::from_encoding_key(&state.key.rsa, Algorithm::RS256)
		.context("Failed to create RSA public JWK")?;
	jwk.common.key_id = Some(state.key.rsa_kid.clone());
	let resp = JwkSet { keys: vec![jwk] };

	Ok(axum::response::Json(resp))
}
