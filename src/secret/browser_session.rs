use axum::RequestPartsExt;
use actix_web::cookie::{Cookie, SameSite};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::config::LiveConfig;
use crate::error::{AuthError, DatabaseError};
use crate::SESSION_COOKIE;

use super::primitive::{UserSecret, UserSecretKind};
use super::metadata::EmptyMetadata;
use super::SecretType;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserSessionSecretKind;

impl UserSecretKind for BrowserSessionSecretKind {
	const PREFIX: SecretType = SecretType::BrowserSession;
	type Metadata = EmptyMetadata;

	async fn duration(config: &LiveConfig) -> chrono::Duration { config.session_duration }
}

pub type BrowserSessionSecret = UserSecret<BrowserSessionSecretKind>;

impl actix_web::FromRequest for BrowserSessionSecret {
	type Error = crate::error::AppError;
	type Future = BoxFuture<'static, std::result::Result<Self, Self::Error>>;

	fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
		let Some(code) = req.cookie(SESSION_COOKIE) else {
			return Box::pin(async { Err(AuthError::NotLoggedIn.into()) });
		};
		let Some(db) = req.app_data::<actix_web::web::Data<crate::Database>>().cloned() else {
			return Box::pin(async { Err(DatabaseError::InstanceError.into()) });
		};

		let code = code.value().to_string();
		Box::pin(async move {
			Self::try_from_string(code, db.get_ref()).await
				.map_err(Into::into)
		})
	}
}

// Here the "consume self when the secret is used" pattern is broken
// as the use-case for this implementation in [handle_magic_link](crate::handle_magic_link::magic_link)
// requires that the structs lives after the transformation to cookie,
// to be made into a proxy code secret, if that's the case.
impl From<&BrowserSessionSecret> for Cookie<'_> {
	fn from(val: &BrowserSessionSecret) -> Cookie<'static> {
		Cookie::build(
			SESSION_COOKIE,
			val.code().to_str_that_i_wont_print(),
		)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish()
	}
}

impl From<&BrowserSessionSecret> for axum_extra::extract::cookie::Cookie<'_> {
	fn from(val: &BrowserSessionSecret) -> axum_extra::extract::cookie::Cookie<'static> {
		axum_extra::extract::cookie::Cookie::build((
			SESSION_COOKIE,
			val.code().to_str_that_i_wont_print(),
		))
		.http_only(true)
		.path("/")
		.build()
	}
}

impl BrowserSessionSecret {
	#[must_use]
	pub fn unset_cookie() -> Cookie<'static> {
		let mut cookie: Cookie<'_> = Cookie::new(SESSION_COOKIE, "");
		cookie.make_removal();
		cookie
	}
}

impl axum::extract::FromRequestParts<crate::AppState> for BrowserSessionSecret {
	// type Rejection = crate::error::AppError;
	type Rejection = axum::http::StatusCode;

	async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &crate::AppState) -> Result<Self, Self::Rejection> {
		// let Ok(code) = parts.extract::<String>().await else {
		// 	return Err(Self::Rejection::BAD_REQUEST);
		// };
		let jar = parts.extract::<axum_extra::extract::CookieJar>().await.unwrap();
		let Some(code) = jar.get(SESSION_COOKIE) else {
			return Err(axum::http::StatusCode::BAD_REQUEST);
		};

		Ok(Self::try_from_string(code.value().to_string(), &state.db).await.unwrap())
	}
}

impl axum::extract::OptionalFromRequestParts<crate::AppState> for BrowserSessionSecret {
	// type Rejection = crate::error::AppError;
	type Rejection = axum::http::StatusCode;

	async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &crate::AppState) -> Result<Option<Self>, Self::Rejection> {
		// let Ok(code) = parts.extract::<String>().await else {
		// 	return Err(Self::Rejection::BAD_REQUEST);
		// };
		let jar = parts.extract::<axum_extra::extract::CookieJar>().await.unwrap();
		let Some(code) = jar.get(SESSION_COOKIE) else {
			return Ok(None);
		};

		Ok(Some(Self::try_from_string(code.value().to_string(), &state.db).await.unwrap()))
	}
}
