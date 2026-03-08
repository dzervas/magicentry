use anyhow::Context as _;
use axum::extract::State;
use axum::response::IntoResponse;
use jsonwebtoken::jwk::{Jwk, JwkSet};

use crate::error::AppError;
use crate::{AppState, JWT_ALGORITHM};

#[axum::debug_handler]
pub async fn handle_jwks(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
	let jwk = Jwk::from_encoding_key(&state.key, JWT_ALGORITHM)
		.context("Failed to create JWK from encoding key")?;
	let resp = JwkSet { keys: vec![jwk] };

	Ok(axum::response::Json(resp))
}
