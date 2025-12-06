use axum::RequestPartsExt;
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AppError, AuthError};
use crate::{AppState, SESSION_COOKIE};

use super::SecretType;
use super::metadata::EmptyMetadata;
use super::primitive::{UserSecret, UserSecretKind};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserSessionSecretKind;

impl UserSecretKind for BrowserSessionSecretKind {
	const PREFIX: SecretType = SecretType::BrowserSession;
	type Metadata = EmptyMetadata;

	async fn duration(config: &LiveConfig) -> chrono::Duration {
		config.session_duration
	}
}

pub type BrowserSessionSecret = UserSecret<BrowserSessionSecretKind>;

// Here the "consume self when the secret is used" pattern is broken
// as the use-case for this implementation in [handle_magic_link](crate::handle_magic_link::magic_link)
// requires that the structs lives after the transformation to cookie,
// to be made into a proxy code secret, if that's the case.
impl From<&BrowserSessionSecret> for Cookie<'_> {
	fn from(val: &BrowserSessionSecret) -> Cookie<'static> {
		Cookie::build((SESSION_COOKIE, val.code().to_str_that_i_wont_print()))
			.http_only(true)
			.path("/")
			.build()
	}
}

impl FromRequestParts<AppState> for BrowserSessionSecret {
	type Rejection = AppError;

	async fn from_request_parts(
		parts: &mut Parts,
		state: &AppState,
	) -> Result<Self, Self::Rejection> {
		let Ok(jar) = parts.extract::<CookieJar>().await;
		let Some(code) = jar.get(SESSION_COOKIE) else {
			return Err(AuthError::NotLoggedIn.into());
		};

		Self::try_from_string(code.value().to_string(), &state.db).await
	}
}

impl OptionalFromRequestParts<AppState> for BrowserSessionSecret {
	type Rejection = AppError;

	async fn from_request_parts(
		parts: &mut Parts,
		state: &AppState,
	) -> Result<Option<Self>, Self::Rejection> {
		let Ok(jar) = parts.extract::<CookieJar>().await;
		let Some(code) = jar.get(SESSION_COOKIE) else {
			return Ok(None);
		};

		// Does this need to bubble the error or return None?
		Ok(Some(
			Self::try_from_string(code.value().to_string(), &state.db).await?,
		))
	}
}
