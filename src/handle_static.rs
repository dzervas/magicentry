use std::fs;

use actix_web::{get, web, HttpResponse};

#[get("/static/{filename}")]
async fn static_files(filename: web::Path<String>) -> HttpResponse {
	let (file, content_type) = match filename.as_str() {
		"main.css" => ("main.build.css", "text/css"),
		"logo.svg" => ("logo.svg", "image/svg+xml"),
		"webauthn.js" => ("webauthn.build.js", "text/javascript"),
		_ => return HttpResponse::NotFound().finish(),
	};

	let content = fs::read_to_string(format!("static/{}", file))
		.unwrap_or_else(|_| panic!("Unable to open static/{}", file));

	HttpResponse::Ok().content_type(content_type).body(content)
}

#[get("/favicon.ico")]
async fn favicon() -> HttpResponse {
	let content = fs::read("static/favicon.ico").expect("Unable to open static/favicon.ico");

	HttpResponse::Ok()
		.content_type("image/x-icon")
		.body(content)
}
