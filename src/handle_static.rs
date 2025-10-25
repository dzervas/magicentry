use std::fs;

use actix_web::{get, web, HttpResponse};

use crate::error::Response;
use anyhow::Context as _;

#[get("/static/{filename}")]
async fn static_files(filename: web::Path<String>) -> Response {
	let (file, content_type) = match filename.as_str() {
		"app-placeholder.svg" => ("app-placeholder.svg", "image/svg+xml"),
		"main.css" => ("css/main.css", "text/css"),
		"logo.svg" => ("logo.svg", "image/svg+xml"),
		"webauthn.js" => ("webauthn.build.js", "text/javascript"),
		_ => return Ok(HttpResponse::NotFound().finish()),
	};

	let content = fs::read_to_string(format!("static/{file}"))
		.context("Failed to read static file")?;

	Ok(HttpResponse::Ok().content_type(content_type).body(content))
}

#[get("/favicon.ico")]
async fn favicon() -> Response {
	let content = fs::read("static/favicon.ico")
		.context("Failed to read favicon.ico file")?;

	Ok(HttpResponse::Ok()
		.content_type("image/x-icon")
		.body(content))
}
