use std::collections::BTreeMap;

use actix_web::http::header::ContentType;
use actix_web::{post, web, HttpResponse};
use chrono::Duration;
use serde::Deserialize;

use crate::database::Database;
use crate::error::Response;
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
	let page = get_partial::<()>("api_key", data, None)?;
	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(page))
}

#[derive(Deserialize)]
struct KeyForm {
	key: String,
}

#[post("/api_key/delete")]
async fn delete(
	browser_session: BrowserSessionSecret,
	form: web::Form<KeyForm>,
	db: web::Data<Database>,
) -> Response {
	ApiKeySecret::delete_with_user(form.key.clone(), browser_session.user(), db.get_ref()).await?;
	Ok(HttpResponse::Found()
		.append_header(("Location", "/"))
		.finish())
}

#[post("/api_key/rotate")]
async fn rotate(
	browser_session: BrowserSessionSecret,
	form: web::Form<KeyForm>,
	db: web::Data<Database>,
) -> Response {
	let new_key =
		ApiKeySecret::rotate_with_user(form.key.clone(), browser_session.user(), db.get_ref())
			.await?;
	let mut data = BTreeMap::new();
	data.insert("key", new_key.code().to_str_that_i_wont_print().to_string());
	let page = get_partial::<()>("api_key", data, None)?;
	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(page))
}

pub fn init(cfg: &mut actix_web::web::ServiceConfig) {
	cfg.service(create).service(delete).service(rotate);
}
