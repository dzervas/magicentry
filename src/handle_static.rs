use std::fs;

use actix_web::{get, web, HttpResponse};

use crate::error::Response;

#[get("/static/{filename}")]
async fn static_files(filename: web::Path<String>) -> Response {
	let (file, content_type) = match filename.as_str() {
		"app-placeholder.svg" => ("app-placeholder.svg", "image/svg+xml"),
		"main.css" => ("main.build.css", "text/css"),
		"logo.svg" => ("logo.svg", "image/svg+xml"),
		"webauthn.js" => ("webauthn.build.js", "text/javascript"),
		_ => return Ok(HttpResponse::NotFound().finish()),
	};

	let content = fs::read_to_string(format!("static/{}", file))?;

	Ok(HttpResponse::Ok().content_type(content_type).body(content))
}

#[get("/favicon.ico")]
async fn favicon() -> Response {
	let content = fs::read("static/favicon.ico")?;

	Ok(HttpResponse::Ok()
		.content_type("image/x-icon")
		.body(content))
}
