use std::{fs, net::SocketAddr, time::Duration};
use hurl::{runner::{RunnerOptionsBuilder, Value}, util::logger::LoggerOptionsBuilder};
use tiny_http::{Response, Server as TinyServer};

use crate::*;

pub async fn app_server() -> (actix_web::dev::Server, Vec<SocketAddr>, sqlx::SqlitePool) {
    Config::reload().await.unwrap();
	let config = CONFIG.read().await;
	println!("config: {:?}", config.services);
	drop(config);
	let db = database::init_database("sqlite::memory:").await.unwrap();

	let (addrs, server) = app_build::build(
		Some("127.0.0.1:0".to_string()),
		db.clone(),
		None,
		None,
	).await;

	(server, addrs, db)
}

/// Starts a minimal fixture server using `tiny_http` in a blocking task
#[must_use]
pub fn fixture_server(db: Database) -> (tokio::task::JoinHandle<()>, u16) {
	let server = TinyServer::http("127.0.0.1:0").expect("failed to bind tiny http server");
	let port = server.server_addr().to_ip().unwrap().port();

	let handle = tokio::task::spawn_blocking(move || {
		for req in server.incoming_requests() {
			let url = req.url().to_string();
			eprintln!("Fixture server received request: {} {}", req.method().as_str(), url);

			if req.method().as_str() == "GET" && url == "/bye" {
				eprintln!("Fixture server: Bye");
				req.respond(Response::from_string("Bye").with_status_code(200)).unwrap();
				break;
			}

			if req.method().as_str() != "GET" || url != "/" {
				eprintln!("Fixture server: Not found");
				req.respond(Response::from_string("Not Found").with_status_code(404)).unwrap();
				continue;
			}

			// Use a blocking runtime to handle the async database query
			let rt = tokio::runtime::Handle::current();
			let data = rt.block_on(async {
				sqlx::query!("SELECT code FROM user_secrets WHERE code LIKE 'me_ll_%' ORDER BY created_at DESC LIMIT 1")
					.fetch_optional(&db)
					.await
					.unwrap()
					.map(|row| row.code)
			});

			eprintln!("Fixture server: Looking for me_ll_ codes");

			// Return the me_ll_ secret as plain text
			if let Some(code) = data {
				let login_link = format!("/login/{code}");
				eprintln!("Fixture server: Returning login link: {login_link}");
				req.respond(Response::from_string(login_link).with_status_code(200)).unwrap();
			} else {
				eprintln!("Fixture server: No me_ll_ codes found");
				req.respond(Response::from_string("No me_ll_ codes found").with_status_code(404)).unwrap();
			}
		}
	});

	(handle, port)
}

pub async fn run_test(hurl_path: &str) {
	eprintln!("\nRunning hurl test: {hurl_path}");

	eprintln!("Starting app server");

	let (server, addrs, db) = app_server().await;
	let _server_handle = tokio::spawn(server);
	let base_url = format!("http://127.0.0.1:{}", addrs[0].port());

	// If this is omitted, the server will not start at all
	eprintln!("Waiting for server to be ready at {base_url}");
	let client = reqwest::Client::new();
	client.get(format!("{base_url}/")).send().await.unwrap();

	eprintln!("Starting fixture server");
	let (_fixture_handle, fixture_port) = fixture_server(db.clone());
	let fixture_url = format!("http://127.0.0.1:{fixture_port}/");

	let content = fs::read_to_string(hurl_path)
		.unwrap_or_else(|e| panic!("Failed to read {hurl_path}: {e}"));
	let mut variables = hurl::runner::VariableSet::new();
	variables.insert("base_url".to_string(), Value::String(base_url));
	variables.insert("fixture_url".to_string(), Value::String(fixture_url.clone()));
	let runner_options = RunnerOptionsBuilder::new()
		.timeout(Duration::from_secs(2))
		.build();
	let logger_options = LoggerOptionsBuilder::new().verbosity(Some(hurl::util::logger::Verbosity::Verbose)).build();
	let hurl_input = hurl_core::input::Input::new(hurl_path);

	eprintln!("Running hurl fr fr");
	let output = hurl::runner::run(&content, Some(&hurl_input), &runner_options, &variables, &logger_options).unwrap();

	// The fixture server is spawned as blocking task, so we need to kill it gracefully
	eprintln!("Killing fixture server");
	client.get(format!("{fixture_url}bye")).send().await.unwrap();

	// Dump user_secrets table for debugging
	eprintln!("\n=== Dumping user_secrets table ===");
	let secrets = sqlx::query!("SELECT code, user, metadata, expires_at, created_at FROM user_secrets ORDER BY created_at DESC")
		.fetch_all(&db)
		.await
		.unwrap_or_else(|e| {
			eprintln!("Failed to query user_secrets: {e}");
			Vec::new()
		});

	if secrets.is_empty() {
		eprintln!("No entries in user_secrets table");
	} else {
		eprintln!("Found {} entries in user_secrets table:", secrets.len());
		let nullstr = "<null>".to_string();
		for (i, secret) in secrets.iter().enumerate() {
			eprintln!("  {}:", i + 1);
			eprintln!("    code: {}", secret.code);
			eprintln!("    user: {}", secret.user);
			eprintln!("    metadata: {}", secret.metadata.as_ref().unwrap_or(&nullstr));
			eprintln!("    expires_at: {}", secret.expires_at);
			eprintln!("    created_at: {}", secret.created_at.unwrap_or_else(chrono::NaiveDateTime::default));
			eprintln!();
		}
	}
	eprintln!("=== End of user_secrets dump ===\n");

	assert!(output.errors().is_empty(), "Hurl did not succeed");
}
