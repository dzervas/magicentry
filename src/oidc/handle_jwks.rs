use anyhow::Context as _;
use axum::response::IntoResponse;
use axum::extract::State;
use jsonwebtoken::jwk::{Jwk, JwkSet};

use crate::{AppState, JWT_ALGORITHM};
use crate::error::AppError;

#[axum::debug_handler]
pub async fn handle_jwks(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
	let jwk = Jwk::from_encoding_key(&state.key, JWT_ALGORITHM)
		.context("Failed to create JWK from encoding key")?;
	let resp = JwkSet { keys: vec![jwk] };

	Ok(axum::response::Json(resp))
}
