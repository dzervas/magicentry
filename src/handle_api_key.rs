use std::collections::BTreeMap;

use actix_web::http::header::ContentType;
use actix_web::{post, web, HttpResponse};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::database::Database;
use crate::error::{AppErrorKind, Response};
use crate::secret::{ApiKeySecret, BrowserSessionSecret};
use crate::utils::get_partial;

#[derive(Deserialize)]
struct CreateForm {
	service: String,
	/// expiration in seconds
	expiration: Option<i64>,
}

#[post("/api_key")]
async fn create(
	browser_session: BrowserSessionSecret,
	form: web::Form<CreateForm>,
	db: web::Data<Database>,
) -> Response {
	let duration = form
		.expiration
		.and_then(Duration::try_seconds)
		.unwrap_or_else(|| chrono::Duration::seconds(0));
	let key = ApiKeySecret::new_with_expiration(
		browser_session.user().clone(),
		form.service.clone(),
		duration,
		db.get_ref(),
	)
	.await?;
	let mut data = BTreeMap::new();
	data.insert("key", key.code().to_str_that_i_wont_print().to_string());
	data.insert("id", key.code().to_str_that_i_wont_print().to_string());
	let page = get_partial::<()>("api_key", data, None)?;
	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(page))
}

#[derive(Deserialize)]
struct IdPath {
	id: String,
}

#[post("/api_key/{id}/delete")]
async fn delete(
	browser_session: BrowserSessionSecret,
	path: web::Path<IdPath>,
	db: web::Data<Database>,
) -> Response {
	let key = ApiKeySecret::try_from_string(path.id.clone(), db.get_ref()).await?;
	if key.user() != browser_session.user() {
		return Err(AppErrorKind::Unauthorized.into());
	}
	key.delete(db.get_ref()).await?;
	Ok(HttpResponse::Found()
		.append_header(("Location", "/"))
		.finish())
}

#[post("/api_key/{id}/rotate")]
async fn rotate(
	browser_session: BrowserSessionSecret,
	path: web::Path<IdPath>,
	form: web::Form<CreateForm>,
	db: web::Data<Database>,
) -> Response {
	let old = ApiKeySecret::try_from_string(path.id.clone(), db.get_ref()).await?;
	if old.user() != browser_session.user() {
		return Err(AppErrorKind::Unauthorized.into());
	}
	let remaining = if old.expires_at() == chrono::NaiveDateTime::MAX {
		chrono::Duration::seconds(0)
	} else {
		old.expires_at() - Utc::now().naive_utc()
	};
	let new_key = ApiKeySecret::new_with_expiration(
		browser_session.user().clone(),
		form.service.clone(),
		remaining,
		db.get_ref(),
	)
	.await?;
	old.delete(db.get_ref()).await?;
	let mut data = BTreeMap::new();
	data.insert("key", new_key.code().to_str_that_i_wont_print().to_string());
	data.insert("id", new_key.code().to_str_that_i_wont_print().to_string());
	let page = get_partial::<()>("api_key", data, None)?;
	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(page))
}

pub fn init(cfg: &mut actix_web::web::ServiceConfig) {
	cfg.service(create).service(delete).service(rotate);
}
