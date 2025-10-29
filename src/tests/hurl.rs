use std::time::Duration;
use std::net::SocketAddr;
use std::fs;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::serve::Serve;
use axum::Router;
use hurl::util::logger::{LoggerOptionsBuilder, Verbosity};
use hurl::runner::{RunnerOptionsBuilder, Value};
use hurl_core::input::Input;
use tokio::net::TcpListener;

use crate::app_build::axum_run;
use crate::utils::tests::*;
use crate::*;

#[axum::debug_handler]
async fn secrets_handler(State(state): State<AppState>) -> impl IntoResponse {
	let data = sqlx::query!("SELECT code FROM user_secrets WHERE code LIKE 'me_ll_%' ORDER BY created_at DESC LIMIT 1")
		.fetch_optional(&state.db)
		.await
		.unwrap()
		.map(|row| row.code);

	if let Some(code) = data {
		let login_link = format!("/login/{code}");
		eprintln!("Fixture server: Returning login link: {login_link}");
		login_link
	} else {
		eprintln!("Fixture server: No me_ll_ codes found");
		"No me_ll_ codes found".to_string()
	}
}

pub async fn app_server() -> (Serve<TcpListener, Router, Router>, SocketAddr, sqlx::SqlitePool) {
    Config::reload().await.unwrap();
	let db = db_connect().await;
	let (addr, server) = axum_run(
		Some("127.0.0.1:0"),
		db.clone(),
		vec![],
		Some(|router| router.route("/secrets", get(secrets_handler))),
	).await;

	(server, addr, db)
}

pub async fn run_test(hurl_path: &str) {
	eprintln!("\nRunning hurl test: {hurl_path}");

	eprintln!("Starting app server");

	let (server, addr, db) = app_server().await;
	let _server_handle = tokio::spawn(async move {
		server.await.unwrap();
	});
	let base_url = format!("http://localhost:{}", addr.port());
	let fixture_url = format!("{base_url}/secrets");

	// If this is omitted, the server will not start at all
	eprintln!("Waiting for server to be ready at {base_url}");
	let client = reqwest::Client::new();
	let resp = client.get(format!("{base_url}/login")).send().await.unwrap();
	assert_eq!(resp.status(), reqwest::StatusCode::OK);

	let content = fs::read_to_string(hurl_path)
		.unwrap_or_else(|e| panic!("Failed to read {hurl_path}: {e}"));

	let mut variables = hurl::runner::VariableSet::new();
	variables.insert("base_url".to_string(), Value::String(base_url));
	variables.insert("fixture_url".to_string(), Value::String(fixture_url.clone()));

	let hurl_input = Input::new(hurl_path);
	let runner_options = RunnerOptionsBuilder::new()
		.timeout(Duration::from_secs(2))
		.build();
	let logger_options = LoggerOptionsBuilder::new()
		.verbosity(Some(Verbosity::VeryVerbose))
		.build();

	eprintln!("Running hurl fr fr");
	let output = hurl::runner::run(
		&content,
		Some(&hurl_input),
		&runner_options,
		&variables,
		&logger_options
	).unwrap();

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
