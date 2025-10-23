use std::{fs, net::SocketAddr};
use hurl::{runner::{RunnerOptionsBuilder, Value}, util::logger::LoggerOptionsBuilder};
use tiny_http::{Response, Server as TinyServer};

use crate::*;

pub async fn app_server() -> (actix_web::dev::Server, Vec<SocketAddr>, sqlx::SqlitePool) {
    ConfigFile::reload().await.unwrap();
	let db = database::init_database("sqlite::memory:").await.unwrap();

	let (addrs, server) = app_build::build(
		Some("127.0.0.1:0".to_string()),
		db.clone(),
		None,
		None,
	).await;

	(server, addrs, db)
}

/// Starts a minimal static file server on 127.0.0.1:8081 serving the `hurl/.link.txt` file.
#[must_use]
pub fn fixture_server(db: Database) -> (tokio::task::JoinHandle<()>, u16) {
	let server = TinyServer::http("127.0.0.1:0").expect("failed to bind tiny http server");
	let port = server.server_addr().to_ip().unwrap().port();
	let handle = tokio::spawn(async move {
		for req in server.incoming_requests() {
			let url = req.url().to_string();
			if req.method().as_str() != "GET" || url != "/" {
				req.respond(Response::from_string("Not Found").with_status_code(404)).unwrap();
				continue;
			}

			let data = sqlx::query!("SELECT code FROM user_secrets")
				.fetch_all(&db)
				.await
				.unwrap()
				.into_iter()
				.map(|row| row.code)
				.collect::<Vec<String>>();

			let json = serde_json::to_string_pretty(&data).unwrap();

			req.respond(Response::from_string(json).with_status_code(200)).unwrap();
		}
	});

	(handle, port)
}

pub async fn run_test(hurl_path: &str) {
	eprintln!("\nRunning hurl test: {hurl_path}");

	let (server, addrs, db) = app_server().await;
	eprintln!("Starting app server");
	let _handle = tokio::spawn(server);
	eprintln!("Starting fixture server");
	let (_fixture_handle, fixture_port) = fixture_server(db);

	eprintln!("Running hurl fr fr");
	let content = fs::read_to_string(hurl_path)
		.unwrap_or_else(|e| panic!("Failed to read {hurl_path}: {e}"));
	let mut variables = hurl::runner::VariableSet::new();
	variables.insert("base_url".to_string(), Value::String(format!("http://127.0.0.1:{}", addrs[0].port())));
	variables.insert("fixture_url".to_string(), Value::String(format!("http://127.0.0.1:{fixture_port}/")));
	let runner_options = RunnerOptionsBuilder::new()
		.timeout(std::time::Duration::from_secs(2))
		.build();
	let logger_options = LoggerOptionsBuilder::new().build();
	let hurl_input = hurl_core::input::Input::new(hurl_path);

	let output = hurl::runner::run(&content, Some(&hurl_input), &runner_options, &variables, &logger_options).unwrap();

	eprintln!("Hurl errors: {:?}", output.errors());

	assert!(output.errors().is_empty(), "Hurl returned errors");
}
